import json
from types import SimpleNamespace

from conftest import login


def enable_passkeys(application, monkeypatch):
    monkeypatch.setitem(application.app.config, "ADMIN_WEBAUTHN_REQUIRED", True)
    monkeypatch.setitem(application.app.config, "WEBAUTHN_ORIGIN", "http://localhost")
    monkeypatch.setitem(application.app.config, "WEBAUTHN_RP_ID", "localhost")


def fake_options(application, monkeypatch):
    monkeypatch.setattr(
        application,
        "options_to_json",
        lambda _options: json.dumps(
            {
                "challenge": "AA",
                "rpId": "localhost",
                "allowCredentials": [],
                "userVerification": "required",
            }
        ),
    )
    monkeypatch.setattr(
        application, "generate_authentication_options", lambda **_kwargs: object()
    )
    monkeypatch.setattr(
        application, "generate_registration_options", lambda **_kwargs: object()
    )


def add_passkey(application):
    admin = application.User.query.filter_by(email="admin@example.test").one()
    passkey = application.AdminPasskey(
        user_id=admin.id,
        name="Test key",
        credential_id=application.bytes_to_base64url(b"credential"),
        public_key=b"public-key-only",
        sign_count=1,
        transports="internal",
    )
    application.db.session.add(passkey)
    application.db.session.commit()
    return admin, passkey


def test_first_admin_login_is_restricted_to_passkey_enrolment(
    seeded_app, client, monkeypatch
):
    enable_passkeys(seeded_app, monkeypatch)

    response = login(client, "admin")
    assert response.status_code == 302
    assert response.location.endswith("/account/passkeys")

    blocked = client.get("/admin")
    assert blocked.status_code == 302
    assert blocked.location.endswith("/account/passkeys")
    assert client.get("/account/passkeys").status_code == 200


def test_admin_enrolment_stores_only_public_credential_and_unlocks_admin(
    seeded_app, client, monkeypatch
):
    enable_passkeys(seeded_app, monkeypatch)
    fake_options(seeded_app, monkeypatch)
    login(client, "admin")

    options = client.post("/account/passkeys/register/options").get_json()
    assert options["challengeId"]

    monkeypatch.setattr(
        seeded_app,
        "verify_registration_response",
        lambda **_kwargs: SimpleNamespace(
            credential_id=b"credential",
            credential_public_key=b"public-key-only",
            sign_count=2,
        ),
    )
    response = client.post(
        "/account/passkeys/register/verify",
        json={
            "challengeId": options["challengeId"],
            "name": "Windows Hello",
            "credential": {
                "id": seeded_app.bytes_to_base64url(b"credential"),
                "response": {"transports": ["internal"]},
            },
        },
    )
    assert response.status_code == 200
    assert response.get_json()["redirect"].endswith("/admin")

    with seeded_app.app.app_context():
        stored = seeded_app.AdminPasskey.query.one()
        assert stored.name == "Windows Hello"
        assert stored.public_key == b"public-key-only"
        assert not hasattr(stored, "private_key")

    assert client.get("/admin").status_code == 200
    replay = client.post(
        "/account/passkeys/register/verify",
        json={"challengeId": options["challengeId"], "credential": {"id": "x"}},
    )
    assert replay.status_code == 400


def test_returning_admin_needs_password_and_passkey(
    seeded_app, client, monkeypatch
):
    enable_passkeys(seeded_app, monkeypatch)
    fake_options(seeded_app, monkeypatch)
    with seeded_app.app.app_context():
        _admin, passkey = add_passkey(seeded_app)
        passkey_id = passkey.id

    password_response = login(client, "admin")
    assert password_response.location.endswith("/admin/mfa")
    with client.session_transaction() as session:
        assert "_user_id" not in session
        assert session["pending_admin_mfa_user_id"]

    options = client.post("/admin/mfa/options").get_json()
    monkeypatch.setattr(
        seeded_app,
        "verify_authentication_response",
        lambda **_kwargs: SimpleNamespace(
            credential_id=b"credential", new_sign_count=4
        ),
    )
    verified = client.post(
        "/admin/mfa/verify",
        json={
            "challengeId": options["challengeId"],
            "credential": {"id": seeded_app.bytes_to_base64url(b"credential")},
        },
    )
    assert verified.status_code == 200
    assert verified.get_json()["redirect"].endswith("/admin")
    with client.session_transaction() as session:
        assert session["_user_id"]
        assert session["admin_step_up_at"]

    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.AdminPasskey, passkey_id).sign_count == 4


def test_stale_admin_session_requires_passkey_step_up_for_mutations(
    seeded_app, client, monkeypatch
):
    enable_passkeys(seeded_app, monkeypatch)
    fake_options(seeded_app, monkeypatch)
    with seeded_app.app.app_context():
        admin, _passkey = add_passkey(seeded_app)
    monkeypatch.setitem(seeded_app.app.config, "ADMIN_WEBAUTHN_REQUIRED", False)
    login(client, "admin")
    monkeypatch.setitem(seeded_app.app.config, "ADMIN_WEBAUTHN_REQUIRED", True)
    with client.session_transaction() as session:
        session["admin_step_up_at"] = 0

    blocked = client.post("/admin/listings/1/approve")
    assert blocked.status_code == 303
    assert blocked.location.endswith("/admin/step-up")

    options = client.post("/admin/step-up/options").get_json()
    monkeypatch.setattr(
        seeded_app,
        "verify_authentication_response",
        lambda **_kwargs: SimpleNamespace(
            credential_id=b"credential", new_sign_count=5
        ),
    )
    verified = client.post(
        "/admin/step-up/verify",
        json={
            "challengeId": options["challengeId"],
            "credential": {"id": seeded_app.bytes_to_base64url(b"credential")},
        },
    )
    assert verified.status_code == 200
    assert verified.get_json()["redirect"].endswith("/admin")

    allowed = client.post("/admin/listings/1/approve")
    assert allowed.status_code == 302


def test_expired_and_single_use_challenges_are_rejected(seeded_app, monkeypatch):
    enable_passkeys(seeded_app, monkeypatch)
    with seeded_app.app.app_context():
        admin = seeded_app.User.query.filter_by(email="admin@example.test").one()
        challenge, _raw = seeded_app._create_webauthn_challenge(admin, "admin_login")
        first = seeded_app._consume_webauthn_challenge(
            challenge.id, admin, "admin_login"
        )
        second = seeded_app._consume_webauthn_challenge(
            challenge.id, admin, "admin_login"
        )
        assert first is not None
        assert second is None

        expired, _raw = seeded_app._create_webauthn_challenge(admin, "admin_login")
        expired.expires_at = seeded_app.utcnow() - seeded_app.timedelta(seconds=1)
        seeded_app.db.session.commit()
        assert seeded_app._consume_webauthn_challenge(
            expired.id, admin, "admin_login"
        ) is None
