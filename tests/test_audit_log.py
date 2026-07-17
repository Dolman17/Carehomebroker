from pathlib import Path

from conftest import login


def test_login_audit_uses_hashed_network_identifier(client, seeded_app):
    response = client.post(
        "/login",
        data={"email": "buyer@example.test", "password": "Testing123!"},
        environ_base={"REMOTE_ADDR": "203.0.113.42"},
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        event = seeded_app.AuditEvent.query.filter_by(
            event_type="auth.login_succeeded"
        ).one()
        assert event.subject_user.email == "buyer@example.test"
        assert event.ip_hash and len(event.ip_hash) == 64
        assert "203.0.113.42" not in event.ip_hash
        assert "203.0.113.42" not in str(event.details)


def test_security_activity_is_user_scoped(client, seeded_app):
    login(client, "buyer")
    response = client.get("/account/security-activity")
    assert response.status_code == 200
    assert b"Signed in" in response.data
    assert b"seller@example.test" not in response.data


def test_admin_audit_log_filters_events(client, seeded_app):
    login(client, "admin")
    with seeded_app.app.app_context():
        seeded_app.db.session.add(
            seeded_app.AuditEvent(
                event_type="admin.example", summary="Distinct audit marker",
                resource_type="listing", resource_id="1", details={},
            )
        )
        seeded_app.db.session.commit()
    response = client.get("/admin/audit-log?event_type=admin.example")
    assert response.status_code == 200
    assert b"Distinct audit marker" in response.data
    response = client.get("/admin/audit-log?event_type=auth.login_failed")
    assert b"Distinct audit marker" not in response.data


def test_non_admin_cannot_view_full_audit_log(client):
    login(client, "buyer")
    response = client.get("/admin/audit-log")
    assert response.status_code == 302


def test_private_document_download_is_authorized_and_audited(
    client, seeded_app, tmp_path
):
    with seeded_app.app.app_context():
        seller = seeded_app.User.query.filter_by(role="seller").one()
        seller_id = seller.id
        profile = seeded_app.SellerProfile.query.filter_by(user_id=seller.id).one()
        stored = "stored.pdf"
        Path(tmp_path, stored).write_bytes(b"private document")
        document = seeded_app.SellerProfileDocument(
            profile_id=profile.id, filename=stored, original_filename="accounts.pdf"
        )
        seeded_app.db.session.add(document)
        seeded_app.db.session.commit()
        document_id = document.id
        seeded_app.app.config["SELLER_DOCS_FOLDER"] = str(tmp_path)

    login(client, "buyer")
    assert client.get(f"/seller/documents/{document_id}/download").status_code == 404
    client.post("/logout")
    login(client, "seller")
    response = client.get(f"/seller/documents/{document_id}/download")
    assert response.status_code == 200
    assert response.data == b"private document"
    with seeded_app.app.app_context():
        event = seeded_app.AuditEvent.query.filter_by(
            event_type="document.downloaded", resource_id=str(document_id)
        ).one()
        assert event.subject_user_id == seller_id
