from conftest import login


def configure_profile(app):
    with app.app.app_context():
        profile = app.BuyerProfile.query.filter_by(user_id=3).one()
        profile.beds_min = 20
        profile.beds_max = 60
        profile.quality_preference = "Good and above"
        profile.deal_structure = "Freehold"
        profile.mandate_review.snapshot_hash = app.buyer_mandate_snapshot_hash(profile)
        app.db.session.commit()


def test_match_explanation_shows_weighted_evidence(client, seeded_app):
    configure_profile(seeded_app)
    with seeded_app.app.app_context():
        listing = seeded_app.db.session.get(seeded_app.Listing, 1)
        profile = seeded_app.BuyerProfile.query.filter_by(user_id=3).one()
        result = seeded_app.explain_buyer_listing_match(listing, profile)
        assert result["score"] == 100
        assert result["coverage"] == 100
        assert result["fit_count"] == 6
        assert sum(item["weight"] for item in result["criteria"]) == 100
    login(client, "buyer")
    page = client.get("/buyer/matches/1")
    assert page.status_code == 200
    assert b"Criterion-by-criterion evidence" in page.data
    assert b"Human decision required" in page.data
    assert b"100%" in page.data


def test_gaps_rank_but_do_not_block_access_or_enquiry(client, seeded_app):
    configure_profile(seeded_app)
    with seeded_app.app.app_context():
        listing = seeded_app.db.session.get(seeded_app.Listing, 1)
        listing.region = "London"
        listing.guide_price_band = "£20,000,000"
        listing.beds = 10
        profile = seeded_app.BuyerProfile.query.filter_by(user_id=3).one()
        result = seeded_app.explain_buyer_listing_match(listing, profile)
        gaps = {item["key"] for item in result["criteria"] if item["status"] == "gap"}
        assert {"region", "budget", "size"} <= gaps
        seeded_app.db.session.commit()
    login(client, "buyer")
    assert client.get("/buyer/matches/1").status_code == 200
    assert client.get("/listings/1").status_code == 200
    response = client.post(
        "/listing/1/enquire", data={"message": "I have context that may change the fit.", "nda": "on"}
    )
    assert response.status_code in {200, 302}


def test_missing_evidence_reduces_coverage_not_fit_score(client, seeded_app):
    configure_profile(seeded_app)
    with seeded_app.app.app_context():
        listing = seeded_app.db.session.get(seeded_app.Listing, 1)
        listing.beds = None
        listing.cqc_rating = None
        listing.tenure = None
        profile = seeded_app.BuyerProfile.query.filter_by(user_id=3).one()
        result = seeded_app.explain_buyer_listing_match(listing, profile)
        assert result["missing_count"] == 3
        assert result["coverage"] == 70
        assert result["score"] == 100


def test_seller_and_admin_see_explanations_without_automatic_decisions(client, seeded_app):
    configure_profile(seeded_app)
    login(client, "seller")
    page = client.get("/seller/buyers?listing_id=1")
    assert page.status_code == 200
    assert b"Why this score?" in page.data
    assert b"retain all introduction decisions" in page.data
    assert client.get("/seller/buyers?listing_id=2").status_code == 404
    client.post("/logout")
    login(client, "admin")
    admin_page = client.get("/admin/matches")
    assert b"coverage" in admin_page.data.lower()
    assert b"assisted ranking only" in admin_page.data
