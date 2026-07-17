from conftest import login
import pytest
from sqlalchemy.exc import IntegrityError


def test_notification_deduplication_is_enforced_by_database(seeded_app):
    with seeded_app.app.app_context():
        seeded_app.db.session.add_all(
            [
                seeded_app.Notification(
                    user_id=3,
                    event_type="test",
                    title="First",
                    body="First event.",
                    dedupe_key="same-event",
                ),
                seeded_app.Notification(
                    user_id=3,
                    event_type="test",
                    title="Duplicate",
                    body="Duplicate event.",
                    dedupe_key="same-event",
                ),
            ]
        )
        with pytest.raises(IntegrityError):
            seeded_app.db.session.commit()
        seeded_app.db.session.rollback()


def test_listing_go_live_creates_one_deduplicated_buyer_alert(client, seeded_app):
    with seeded_app.app.app_context():
        seeded_app.db.session.add(
            seeded_app.SavedSearch(
                buyer_id=3,
                name="Midlands care",
                region="Midlands",
                email_alerts=True,
            )
        )
        listing = seeded_app.Listing(
            seller_id=2,
            listing_code="OL-NOTIFY-1",
            title="New matching opportunity",
            region="Midlands",
            care_type="Healthcare & Social Care",
            status="draft",
        )
        seeded_app.db.session.add(listing)
        seeded_app.db.session.commit()
        listing_id = listing.id

    login(client, "seller")
    assert client.post(
        f"/seller/listings/{listing_id}/status", data={"status": "live"}
    ).status_code == 302
    assert client.post(
        f"/seller/listings/{listing_id}/status", data={"status": "live"}
    ).status_code == 302

    with seeded_app.app.app_context():
        notifications = seeded_app.Notification.query.filter_by(
            user_id=3, dedupe_key=f"listing-match:{listing_id}"
        ).all()
        assert len(notifications) == 1
        assert "Saved search: Midlands care" in notifications[0].body
        assert notifications[0].email_sent_at is None


def test_notification_center_marks_only_owned_notification_read(client, seeded_app):
    with seeded_app.app.app_context():
        owned = seeded_app.Notification(
            user_id=3,
            event_type="test",
            title="Buyer update",
            body="A useful update.",
            target_url="/buyer/dashboard",
            dedupe_key="test:buyer",
        )
        other = seeded_app.Notification(
            user_id=2,
            event_type="test",
            title="Seller update",
            body="Another update.",
            dedupe_key="test:seller",
        )
        seeded_app.db.session.add_all([owned, other])
        seeded_app.db.session.commit()
        owned_id, other_id = owned.id, other.id

    login(client, "buyer")
    page = client.get("/notifications")
    assert page.status_code == 200
    assert b"Buyer update" in page.data
    assert b"Seller update" not in page.data
    assert client.post(f"/notifications/{other_id}/open").status_code == 404

    opened = client.post(f"/notifications/{owned_id}/open")
    assert opened.status_code == 302
    assert opened.headers["Location"].endswith("/buyer/dashboard")
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(
            seeded_app.Notification, owned_id
        ).read_at is not None


def test_immediate_preference_delivers_enquiry_email(client, seeded_app, monkeypatch):
    sent = []
    monkeypatch.setattr(
        seeded_app,
        "send_email",
        lambda recipient, subject, body, **_kwargs: sent.append(
            (recipient, subject, body)
        ) or True,
    )
    with seeded_app.app.app_context():
        seeded_app.db.session.add(
            seeded_app.NotificationPreference(user_id=2, email_mode="immediate")
        )
        seeded_app.db.session.commit()

    login(client, "buyer")
    response = client.post(
        "/listings/1",
        data={"message": "I would like to discuss this business.", "nda_accepted": "1"},
    )
    assert response.status_code == 302
    assert sent and sent[0][0] == "seller@example.test"
    with seeded_app.app.app_context():
        notification = seeded_app.Notification.query.filter_by(
            user_id=2, event_type="new_enquiry"
        ).one()
        assert notification.email_sent_at is not None


def test_weekly_digest_delivers_queued_events_and_marks_them_sent(
    client, seeded_app, monkeypatch
):
    sent = []
    monkeypatch.setattr(
        seeded_app,
        "send_email",
        lambda recipient, subject, body, **_kwargs: sent.append(
            (recipient, subject, body)
        ) or True,
    )
    with seeded_app.app.app_context():
        seeded_app.db.session.add_all(
            [
                seeded_app.NotificationPreference(user_id=3, email_mode="off"),
                seeded_app.Notification(
                    user_id=2,
                    event_type="transaction_update",
                    title="Deal milestone reached",
                    body="The transaction moved to due diligence.",
                    target_url="/seller/dashboard",
                    dedupe_key="deal:test:milestone",
                ),
            ]
        )
        seeded_app.db.session.commit()

    response = client.get("/tasks/send_weekly_digest?token=test-digest-token")
    assert response.status_code == 200
    assert len(sent) == 1
    assert sent[0][0] == "seller@example.test"
    assert "Deal milestone reached" in sent[0][2]
    with seeded_app.app.app_context():
        notification = seeded_app.Notification.query.filter_by(
            dedupe_key="deal:test:milestone"
        ).one()
        assert notification.digest_sent_at is not None


def test_user_can_change_notification_email_mode(client, seeded_app):
    login(client, "buyer")
    response = client.post(
        "/notifications/preferences", data={"email_mode": "immediate"}
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        preference = seeded_app.NotificationPreference.query.filter_by(
            user_id=3
        ).one()
        assert preference.email_mode == "immediate"
