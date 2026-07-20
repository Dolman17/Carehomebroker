from datetime import timedelta

from conftest import login


def prepare_stripe_subscription(app):
    with app.app.app_context():
        subscription = app.Subscription.query.filter_by(user_id=3, tier="premium").one()
        subscription.stripe_subscription_id = "sub_ownerlane_1"
        subscription.stripe_customer_id = "cus_ownerlane_1"
        subscription.stripe_status = "active"
        subscription.last_entitlement_reason = "Stripe subscription is active."
        subscription.renews_at = app.utcnow() + timedelta(days=30)
        app.db.session.commit()
        return subscription.id


def deliver(client, app, monkeypatch, event):
    app.app.config["STRIPE_WEBHOOK_SECRET"] = "whsec_test"
    monkeypatch.setattr(
        app.stripe.Webhook,
        "construct_event",
        lambda payload, sig_header, secret: event,
    )
    return client.post(
        "/webhooks/stripe",
        data=b"signed payload",
        headers={"Stripe-Signature": "test-signature"},
    )


def invoice_event(event_id, event_type):
    return {
        "id": event_id,
        "type": event_type,
        "data": {"object": {
            "id": f"in_{event_id}",
            "subscription": "sub_ownerlane_1",
            "attempt_count": 1,
            "next_payment_attempt": 1784600000,
        }},
    }


def subscription_event(event_id, status, created=None):
    event = {
        "id": event_id,
        "type": "customer.subscription.updated",
        "data": {"object": {
            "id": "sub_ownerlane_1",
            "status": status,
            "current_period_end": 1787000000,
        }},
    }
    if created is not None:
        event["created"] = created
    return event


def test_failed_payment_starts_grace_once_and_prompts_customer(client, seeded_app, monkeypatch):
    prepare_stripe_subscription(seeded_app)
    event = invoice_event("evt_failed_1", "invoice.payment_failed")
    assert deliver(client, seeded_app, monkeypatch, event).status_code == 200
    assert deliver(client, seeded_app, monkeypatch, event).status_code == 200

    with seeded_app.app.app_context():
        subscription = seeded_app.Subscription.query.filter_by(
            stripe_subscription_id="sub_ownerlane_1"
        ).one()
        original_grace_end = subscription.grace_period_ends_at
        assert subscription.stripe_status == "past_due"
        assert seeded_app.subscription_access_state(subscription) == "grace"
        assert seeded_app.has_active_subscription(subscription.user, "buyer", "premium")
        assert seeded_app.SubscriptionEntitlementEvent.query.count() == 1
        assert seeded_app.Notification.query.filter_by(
            user_id=3, dedupe_key="billing:evt_failed_1"
        ).count() == 1

    later_failure = invoice_event("evt_failed_2", "invoice.payment_failed")
    assert deliver(client, seeded_app, monkeypatch, later_failure).status_code == 200
    with seeded_app.app.app_context():
        subscription = seeded_app.Subscription.query.filter_by(
            stripe_subscription_id="sub_ownerlane_1"
        ).one()
        assert subscription.grace_period_ends_at == original_grace_end

    login(client, "buyer")
    page = client.get("/buyer/dashboard")
    assert b"Payment failed" in page.data
    assert b"Fix payment" in page.data


def test_expired_grace_restricts_features_without_deleting_account(client, seeded_app, monkeypatch):
    prepare_stripe_subscription(seeded_app)
    deliver(client, seeded_app, monkeypatch, invoice_event("evt_failed_expiry", "invoice.payment_failed"))
    with seeded_app.app.app_context():
        subscription = seeded_app.Subscription.query.filter_by(
            stripe_subscription_id="sub_ownerlane_1"
        ).one()
        subscription.grace_period_ends_at = seeded_app.utcnow() - timedelta(seconds=1)
        seeded_app.db.session.commit()
        assert not seeded_app.has_active_subscription(subscription.user, "buyer", "premium")
        assert seeded_app.db.session.get(seeded_app.User, 3) is not None

    login(client, "buyer")
    recovery = client.get("/billing/recovery")
    assert recovery.status_code == 200
    assert b"Premium features are paused" in recovery.data
    assert client.get("/buyer/matches/1").status_code == 302
    assert client.get("/buyer/matches/1").headers["Location"].endswith("/billing/recovery")


def test_successful_invoice_recovers_access_automatically(client, seeded_app, monkeypatch):
    prepare_stripe_subscription(seeded_app)
    deliver(client, seeded_app, monkeypatch, invoice_event("evt_failed_recover", "invoice.payment_failed"))
    assert deliver(
        client, seeded_app, monkeypatch,
        invoice_event("evt_paid_recover", "invoice.payment_succeeded"),
    ).status_code == 200

    with seeded_app.app.app_context():
        subscription = seeded_app.Subscription.query.filter_by(
            stripe_subscription_id="sub_ownerlane_1"
        ).one()
        assert subscription.stripe_status == "active"
        assert subscription.grace_period_ends_at is None
        assert subscription.payment_failed_at is None
        assert subscription.last_payment_at is not None
        assert seeded_app.subscription_access_state(subscription) == "active"
        assert seeded_app.SubscriptionEntitlementEvent.query.count() == 2


def test_terminal_status_restricts_access_but_portal_remains_available(client, seeded_app, monkeypatch):
    prepare_stripe_subscription(seeded_app)
    assert deliver(
        client, seeded_app, monkeypatch,
        subscription_event("evt_unpaid", "unpaid"),
    ).status_code == 200
    with seeded_app.app.app_context():
        subscription = seeded_app.Subscription.query.filter_by(
            stripe_subscription_id="sub_ownerlane_1"
        ).one()
        assert subscription.is_active is False
        assert seeded_app.subscription_access_state(subscription) == "restricted"

    seeded_app.app.config["STRIPE_SECRET_KEY"] = "sk_test"
    monkeypatch.setattr(
        seeded_app.stripe.billing_portal.Session,
        "create",
        lambda **kwargs: type("Portal", (), {"url": "https://billing.stripe.test/session"})(),
    )
    login(client, "buyer")
    response = client.post("/billing/portal")
    assert response.status_code == 303
    assert response.headers["Location"] == "https://billing.stripe.test/session"


def test_admin_can_review_entitlement_decision_history(client, seeded_app, monkeypatch):
    prepare_stripe_subscription(seeded_app)
    deliver(client, seeded_app, monkeypatch, invoice_event("evt_admin_audit", "invoice.payment_failed"))
    login(client, "admin")
    page = client.get("/admin/subscriptions?access=grace")
    assert page.status_code == 200
    assert b"Entitlement decision history" in page.data
    assert b"evt_admin_audit" not in page.data
    assert b"Stripe reported that the latest subscription invoice requires payment attention" in page.data
    assert b"active" in page.data and b"grace" in page.data


def test_out_of_order_stripe_event_cannot_restore_newer_restriction(client, seeded_app, monkeypatch):
    prepare_stripe_subscription(seeded_app)
    deliver(
        client, seeded_app, monkeypatch,
        subscription_event("evt_new_unpaid", "unpaid", created=200),
    )
    deliver(
        client, seeded_app, monkeypatch,
        subscription_event("evt_old_active", "active", created=100),
    )
    with seeded_app.app.app_context():
        subscription = seeded_app.Subscription.query.filter_by(
            stripe_subscription_id="sub_ownerlane_1"
        ).one()
        assert subscription.stripe_status == "unpaid"
        assert seeded_app.subscription_access_state(subscription) == "restricted"
        ignored = seeded_app.SubscriptionEntitlementEvent.query.filter_by(
            stripe_event_id="evt_old_active"
        ).one()
        assert ignored.access_state == "restricted"
        assert ignored.details["ignored_as_stale"] is True
