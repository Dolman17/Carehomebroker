from datetime import timedelta

from conftest import login


def test_listing_views_are_aggregated_without_raw_identity(client, seeded_app):
    assert client.get("/listings/1", headers={"User-Agent": "Analytics test"}).status_code == 200
    assert client.get("/listings/1", headers={"User-Agent": "Analytics test"}).status_code == 200
    with seeded_app.app.app_context():
        events = seeded_app.ListingAnalyticsEvent.query.filter_by(
            listing_id=1, event_type="view"
        ).all()
        assert len(events) == 2
        assert len({event.visitor_hash for event in events}) == 1
        assert len(events[0].visitor_hash) == 64
        assert "127.0.0.1" not in events[0].visitor_hash

    login(client, "seller")
    assert client.get("/listings/1").status_code == 200
    with seeded_app.app.app_context():
        assert seeded_app.ListingAnalyticsEvent.query.filter_by(
            listing_id=1, event_type="view"
        ).count() == 2


def test_shortlist_add_and_remove_activity_is_retained(client, seeded_app):
    login(client, "buyer")
    assert client.post("/listings/1/toggle-shortlist").status_code == 302
    assert client.post("/listings/1/toggle-shortlist").status_code == 302
    with seeded_app.app.app_context():
        events = seeded_app.ListingAnalyticsEvent.query.filter_by(listing_id=1).order_by(
            seeded_app.ListingAnalyticsEvent.id
        ).all()
        assert [event.event_type for event in events] == [
            "shortlist_added", "shortlist_removed"
        ]
        assert seeded_app.ShortlistItem.query.count() == 0


def test_analytics_snapshot_combines_funnel_quality_and_stage_timing(seeded_app):
    with seeded_app.app.app_context():
        now = seeded_app.utcnow()
        listing = seeded_app.db.session.get(seeded_app.Listing, 1)
        seeded_app.db.session.add_all([
            seeded_app.ListingAnalyticsEvent(
                listing_id=1, event_type="view", visitor_hash="a" * 64,
                occurred_at=now - timedelta(days=3),
            ),
            seeded_app.ListingAnalyticsEvent(
                listing_id=1, event_type="view", visitor_hash="a" * 64,
                occurred_at=now - timedelta(days=2),
            ),
            seeded_app.ListingAnalyticsEvent(
                listing_id=1, event_type="view", visitor_hash="b" * 64,
                occurred_at=now - timedelta(days=1),
            ),
            seeded_app.ListingAnalyticsEvent(
                listing_id=1, event_type="shortlist_added", visitor_hash="a" * 64,
                occurred_at=now - timedelta(days=1),
            ),
            seeded_app.ShortlistItem(buyer_id=3, listing_id=1),
            seeded_app.Enquiry(
                listing_id=1, buyer_id=3, message="Interested", nda_accepted=True,
                created_at=now - timedelta(days=4),
            ),
        ])
        intro = seeded_app.Introduction(
            buyer_id=3, seller_id=2, listing_id=1, status="viewing",
            created_at=now - timedelta(days=10), updated_at=now,
        )
        seeded_app.db.session.add(intro)
        seeded_app.db.session.flush()
        seeded_app.db.session.add_all([
            seeded_app.IntroductionStatusHistory(
                introduction_id=intro.id, old_status="initiated", new_status="viewing",
                changed_at=now - timedelta(days=5), changed_by_user_id=1,
            ),
            seeded_app.StructuredOffer(
                introduction_id=intro.id, sequence=1, created_by_id=3, recipient_id=2,
                amount_minor=100000000, currency="GBP", status="accepted",
                created_at=now - timedelta(days=2), responded_at=now - timedelta(days=1),
            ),
            seeded_app.BuyerQualification(
                user_id=3, identity_status="verified", business_status="verified",
                funds_status="verified",
            ),
        ])
        seeded_app.db.session.commit()

        snapshot = seeded_app._seller_analytics_snapshot(
            2, [listing], now - timedelta(days=30), now
        )
        assert snapshot["summary"] == {
            "views": 3, "unique_visitors": 2, "current_shortlists": 1,
            "shortlist_adds": 1, "enquiries": 1, "introductions": 1,
            "offers": 1, "accepted": 1, "completed": 0,
        }
        assert snapshot["listing_rows"][0]["enquiry_conversion"] == 50.0
        assert snapshot["match_quality"]["strong"] == 1
        assert snapshot["match_quality"]["verified"] == 1
        assert snapshot["qualification_quality"]["verified"] == 1
        timing = {row["status"]: row["days"] for row in snapshot["stage_timing"]}
        assert timing == {"initiated": 5.0, "viewing": 5.0}


def test_seller_analytics_page_supports_filters_and_hides_buyer_identity(client, seeded_app):
    login(client, "seller")
    page = client.get("/seller/analytics?listing_id=1&period=90")
    assert page.status_code == 200
    assert b"Seller analytics" in page.data
    assert b"Transaction funnel" in page.data
    assert b"Buyer match quality" in page.data
    assert b"buyer@example.test" not in page.data


def test_seller_cannot_filter_analytics_to_someone_elses_listing(client, seeded_app):
    with seeded_app.app.app_context():
        other = seeded_app.User(
            email="other-seller@example.test", role="seller",
            email_verified_at=seeded_app.utcnow(),
        )
        other.set_password("Testing123!")
        seeded_app.db.session.add(other)
        seeded_app.db.session.flush()
        listing = seeded_app.Listing(
            seller_id=other.id, title="Other seller listing", status="live"
        )
        seeded_app.db.session.add(listing)
        seeded_app.db.session.commit()
        listing_id = listing.id
    login(client, "seller")
    assert client.get(f"/seller/analytics?listing_id={listing_id}").status_code == 404


def test_buyer_and_anonymous_users_cannot_open_seller_analytics(client, seeded_app):
    assert client.get("/seller/analytics").status_code == 302
    login(client, "buyer")
    assert client.get("/seller/analytics").status_code == 302
