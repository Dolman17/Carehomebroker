import hashlib
import hmac
import json

from conftest import login


def create_token(app, user_id=3, scopes="listings:read", team_id=None):
    raw = "ol_live_test_" + str(user_id) + scopes.replace(":", "_")
    token = app.IntegrationApiToken(
        user_id=user_id,
        team_id=team_id,
        name="Test token",
        token_prefix=raw[:16],
        token_hash=app.integration_token_hash(raw),
        scopes=scopes,
    )
    app.db.session.add(token)
    app.db.session.commit()
    return raw, token.id


def public_dns(*args, **kwargs):
    return [(2, 1, 6, "", ("93.184.216.34", 443))]


def test_api_token_is_shown_once_hashed_and_revocable(client, seeded_app):
    login(client, "buyer")
    response = client.post(
        "/integrations/api-tokens",
        data={"name": "My CRM", "scopes": ["listings:read", "not:allowed"]},
    )
    assert response.status_code == 200
    first_page = response
    assert b"ol_live_" in first_page.data
    assert b"not:allowed" not in first_page.data
    raw_token = first_page.get_data(as_text=True).split("ol_live_", 1)[1].split("<", 1)[0]
    assert raw_token.encode() not in client.get("/integrations").data
    with seeded_app.app.app_context():
        token = seeded_app.IntegrationApiToken.query.one()
        assert token.token_hash not in first_page.get_data(as_text=True)
        assert token.scopes == "listings:read"
        token_id = token.id
    assert client.post(f"/integrations/api-tokens/{token_id}/revoke").status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.IntegrationApiToken, token_id).revoked_at


def test_versioned_api_enforces_auth_scopes_and_confidentiality(client, seeded_app):
    assert client.get("/api/v1/listings").status_code == 401
    with seeded_app.app.app_context():
        profile_raw, _ = create_token(seeded_app, scopes="profile:read")
        listing_raw, listing_token_id = create_token(seeded_app)
        subscription = seeded_app.Subscription.query.filter_by(user_id=3).one()
        subscription.is_active = False
        seeded_app.db.session.commit()
    assert client.get("/api/v1/listings", headers={"Authorization": f"Bearer {profile_raw}"}).status_code == 403
    response = client.get("/api/v1/listings", headers={"Authorization": f"Bearer {listing_raw}"})
    assert response.status_code == 200
    row = response.get_json()["data"][0]
    assert row["title"] == "Confidential business"
    assert row["asking_price_minor"] is None
    assert "created_at" in row and "updated_at" not in row
    with seeded_app.app.app_context():
        token = seeded_app.db.session.get(seeded_app.IntegrationApiToken, listing_token_id)
        assert token.last_used_at is not None
        token.revoked_at = seeded_app.utcnow()
        seeded_app.db.session.commit()
    assert client.get("/api/v1/listings", headers={"Authorization": f"Bearer {listing_raw}"}).status_code == 401


def test_team_token_stops_working_when_membership_is_removed(client, seeded_app):
    with seeded_app.app.app_context():
        team = seeded_app.Team(name="Buyer group", team_type="buyer", created_by_id=3)
        seeded_app.db.session.add(team)
        seeded_app.db.session.flush()
        membership = seeded_app.TeamMembership(team_id=team.id, user_id=3, role="owner", status="active")
        seeded_app.db.session.add(membership)
        seeded_app.db.session.commit()
        raw, _ = create_token(seeded_app, team_id=team.id)
        membership.status = "removed"
        seeded_app.db.session.commit()
    response = client.get("/api/v1/listings", headers={"Authorization": f"Bearer {raw}"})
    assert response.status_code == 403
    assert response.get_json()["error"] == "team_access_revoked"


def test_webhook_registration_rejects_ssrf_and_reveals_secret_once(client, seeded_app, monkeypatch):
    login(client, "seller")
    response = client.post("/integrations/webhooks", data={
        "name": "Unsafe", "url": "https://127.0.0.1/hook", "event_types": "listing.updated",
    }, follow_redirects=True)
    assert b"not allowed" in response.data
    with seeded_app.app.app_context():
        assert seeded_app.WebhookEndpoint.query.count() == 0
    monkeypatch.setattr(seeded_app.socket, "getaddrinfo", public_dns)
    response = client.post("/integrations/webhooks", data={
        "name": "CRM", "url": "https://hooks.example.test/ownerlane",
        "event_types": ["listing.updated", "offer.accepted"],
    })
    assert response.status_code == 200
    page = response
    with seeded_app.app.app_context():
        endpoint = seeded_app.WebhookEndpoint.query.one()
        secret = seeded_app.webhook_signing_secret(endpoint)
        assert secret.encode() in page.data
        assert endpoint.signing_salt != secret
    assert secret.encode() not in client.get("/integrations").data


def test_webhook_worker_signs_delivery_and_retries(client, seeded_app, monkeypatch):
    captured = {}

    class Response:
        status_code = 204
        text = ""

    def post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return Response()

    monkeypatch.setattr(seeded_app, "validate_webhook_url", lambda url: (url, None))
    monkeypatch.setattr(seeded_app.http_requests, "post", post)
    with seeded_app.app.app_context():
        endpoint = seeded_app.WebhookEndpoint(
            user_id=2, name="CRM", url="https://hooks.example.test/ownerlane",
            signing_salt="a" * 64, event_types="listing.updated",
        )
        seeded_app.db.session.add(endpoint)
        seeded_app.db.session.commit()
        assert seeded_app.queue_integration_event("listing.updated", {"listing_id": 1}, user_id=2) == 1
        delivery_id = seeded_app.WebhookDelivery.query.one().id
        secret = seeded_app.webhook_signing_secret(endpoint)
    assert client.post("/tasks/deliver-webhooks").status_code == 403
    response = client.post(
        "/tasks/deliver-webhooks", headers={"Authorization": "Bearer test-webhook-token"}
    )
    assert response.status_code == 200
    timestamp = captured["headers"]["X-Ownerlane-Timestamp"]
    body = captured["data"].decode()
    expected = hmac.new(secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()
    assert captured["headers"]["X-Ownerlane-Signature"] == f"sha256={expected}"
    assert captured["allow_redirects"] is False
    with seeded_app.app.app_context():
        delivery = seeded_app.db.session.get(seeded_app.WebhookDelivery, delivery_id)
        assert delivery.status == "delivered" and delivery.attempts == 1

    class Failure:
        status_code = 500
        text = "temporary"

    monkeypatch.setattr(seeded_app.http_requests, "post", lambda *args, **kwargs: Failure())
    with seeded_app.app.app_context():
        endpoint = seeded_app.WebhookEndpoint.query.one()
        failed = seeded_app.WebhookDelivery(
            endpoint_id=endpoint.id, event_id="failure-event", event_type="listing.updated",
            payload={"id": "failure-event", "type": "listing.updated", "data": {}}, attempts=4,
        )
        seeded_app.db.session.add(failed)
        seeded_app.db.session.commit()
        failed_id = failed.id
    client.post("/tasks/deliver-webhooks", headers={"Authorization": "Bearer test-webhook-token"})
    with seeded_app.app.app_context():
        failed = seeded_app.db.session.get(seeded_app.WebhookDelivery, failed_id)
        assert failed.status == "failed" and failed.attempts == 5


def test_crm_export_is_role_scoped_and_formula_safe(client, seeded_app):
    with seeded_app.app.app_context():
        seeded_app.BuyerProfile.query.filter_by(user_id=3).one().business_name = "=IMPORTDATA(unsafe)"
        seeded_app.db.session.add(seeded_app.Introduction(
            buyer_id=3, seller_id=2, listing_id=1, status="initiated"
        ))
        seeded_app.db.session.commit()
    login(client, "seller")
    response = client.get("/integrations/crm-export.csv")
    assert response.status_code == 200
    assert response.headers["Content-Disposition"].endswith("ownerlane-crm-export.csv")
    assert "'=IMPORTDATA(unsafe)" in response.get_data(as_text=True)
    assert "buyer@example.test" in response.get_data(as_text=True)
