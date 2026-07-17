from datetime import timedelta

from conftest import login


def test_registration_requires_email_verification(client, seeded_app):
    response = client.post(
        "/register/buyer",
        data={"email": "newbuyer@example.test", "password": "StrongPass123!"},
    )
    assert response.status_code == 302

    with seeded_app.app.app_context():
        user = seeded_app.User.query.filter_by(email="newbuyer@example.test").one()
        assert user.email_verified_at is None
        token = seeded_app.generate_auth_token(user, "verify-email")

    blocked_login = client.post(
        "/login",
        data={"email": "newbuyer@example.test", "password": "StrongPass123!"},
    )
    assert blocked_login.status_code == 403
    assert b"Verify your email" in blocked_login.data

    verified = client.get(f"/verify-email/{token}")
    assert verified.status_code == 302
    successful_login = client.post(
        "/login",
        data={"email": "newbuyer@example.test", "password": "StrongPass123!"},
    )
    assert successful_login.status_code == 302


def test_password_reset_token_is_expiring_and_single_use(client, seeded_app):
    with seeded_app.app.app_context():
        user = seeded_app.User.query.filter_by(email="buyer@example.test").one()
        token = seeded_app.generate_auth_token(user, "password-reset")

    response = client.post(
        f"/reset-password/{token}",
        data={
            "password": "ChangedPass123!",
            "password_confirmation": "ChangedPass123!",
        },
    )
    assert response.status_code == 302

    reused = client.get(f"/reset-password/{token}")
    assert reused.status_code == 302
    assert reused.headers["Location"].endswith("/forgot-password")

    old_password = client.post(
        "/login",
        data={"email": "buyer@example.test", "password": "Testing123!"},
    )
    assert old_password.status_code == 200
    new_password = client.post(
        "/login",
        data={"email": "buyer@example.test", "password": "ChangedPass123!"},
    )
    assert new_password.status_code == 302


def test_password_reset_request_does_not_disclose_accounts(client, seeded_app, monkeypatch):
    recipients = []
    monkeypatch.setattr(
        seeded_app,
        "send_email",
        lambda recipient, *_args, **_kwargs: recipients.append(recipient) or True,
    )
    known = client.post(
        "/forgot-password",
        data={"email": "buyer@example.test"},
        follow_redirects=True,
    )
    unknown = client.post(
        "/forgot-password",
        data={"email": "nobody@example.test"},
        follow_redirects=True,
    )
    generic = b"If an account exists for that email"
    assert generic in known.data
    assert generic in unknown.data
    assert recipients == ["buyer@example.test"]


def test_authentication_emails_are_rate_limited(client, seeded_app, monkeypatch):
    recipients = []
    monkeypatch.setattr(
        seeded_app,
        "send_email",
        lambda recipient, *_args, **_kwargs: recipients.append(recipient) or True,
    )
    for _ in range(4):
        response = client.post(
            "/forgot-password",
            data={"email": "buyer@example.test"},
        )
        assert response.status_code == 302
    assert recipients == ["buyer@example.test"] * 3


def test_authentication_links_use_the_configured_public_origin(seeded_app, monkeypatch):
    messages = []
    monkeypatch.setattr(
        seeded_app,
        "send_email",
        lambda recipient, subject, body, **_kwargs: messages.append(body) or True,
    )
    seeded_app.app.config["PUBLIC_BASE_URL"] = "https://ownerlane.example"
    with seeded_app.app.test_request_context(base_url="http://untrusted.example"):
        user = seeded_app.User.query.filter_by(email="buyer@example.test").one()
        assert seeded_app.send_password_reset_email(user) is True
    assert "https://ownerlane.example/reset-password/" in messages[0]
    assert "untrusted.example" not in messages[0]


def test_login_throttling_blocks_repeated_failures(client, seeded_app):
    seeded_app.app.config.update(LOGIN_FAILURE_LIMIT=3, LOGIN_LOCKOUT_SECONDS=900)
    credentials = {"email": "buyer@example.test", "password": "wrong-password"}
    assert client.post("/login", data=credentials).status_code == 200
    assert client.post("/login", data=credentials).status_code == 200
    assert client.post("/login", data=credentials).status_code == 429

    locked = client.post(
        "/login",
        data={"email": "buyer@example.test", "password": "Testing123!"},
    )
    assert locked.status_code == 429

    with seeded_app.app.app_context():
        attempt = seeded_app.LoginAttempt.query.one()
        attempt.blocked_until = seeded_app.utcnow() - timedelta(seconds=1)
        seeded_app.db.session.commit()

    assert login(client, "buyer").status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.LoginAttempt.query.count() == 0


def test_admin_sessions_ignore_remember_me_and_expire_when_idle(client, seeded_app):
    response = client.post(
        "/login",
        data={
            "email": "admin@example.test",
            "password": "Testing123!",
            "remember": "1",
        },
    )
    assert response.status_code == 302
    assert "remember_token=" not in "\n".join(response.headers.getlist("Set-Cookie"))

    with client.session_transaction() as browser_session:
        browser_session["admin_last_activity"] = 0

    expired = client.get("/admin")
    assert expired.status_code == 302
    assert "/login?next=/admin" in expired.headers["Location"]
    assert client.get("/admin").status_code == 302
