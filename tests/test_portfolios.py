import pytest
from sqlalchemy.exc import IntegrityError

from conftest import login


def make_second_listing(app, *, status="live", seller_id=2, team_id=None):
    with app.app.app_context():
        listing = app.Listing(
            seller_id=seller_id, team_id=team_id, listing_code="CH-0003",
            title="SECOND SECRET BUSINESS", region="North West",
            care_type="Healthcare", is_confidential=True, status=status,
        )
        app.db.session.add(listing)
        app.db.session.commit()
        return listing.id


def create_portfolio(client, app, *, sale_mode="either"):
    second_id = make_second_listing(app)
    login(client, "seller")
    response = client.post("/seller/portfolios/new", data={
        "title": "National operator group",
        "summary": "A multi-site opportunity",
        "sale_mode": sale_mode,
        "asking_price": "7500000",
        "currency": "GBP",
        "is_confidential": "on",
        "listing_ids": ["1", str(second_id)],
    })
    assert response.status_code == 302
    with app.app.app_context():
        return app.Portfolio.query.one().id


def test_seller_creates_portfolio_with_default_lot(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    with seeded_app.app.app_context():
        portfolio = seeded_app.db.session.get(seeded_app.Portfolio, portfolio_id)
        assert portfolio.portfolio_code == "PF-0001"
        assert portfolio.sale_mode == "either"
        assert portfolio.asking_price_minor == 750000000
        assert portfolio.status == "draft"
        assert portfolio.listing_count == 2
        assert len(portfolio.lots) == 1
        assert {item.listing_id for item in portfolio.lots[0].items} == {1, 3}
        assert seeded_app.AuditEvent.query.filter_by(event_type="portfolio.created").count() == 1


def test_portfolio_publication_requires_live_constituents(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    with seeded_app.app.app_context():
        seeded_app.db.session.get(seeded_app.Listing, 3).status = "draft"
        seeded_app.db.session.commit()
    response = client.post(
        f"/seller/portfolios/{portfolio_id}/status",
        data={"status": "live"}, follow_redirects=True,
    )
    assert b"Every portfolio listing must be live" in response.data
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.Portfolio, portfolio_id).status == "draft"
        seeded_app.db.session.get(seeded_app.Listing, 3).status = "live"
        seeded_app.db.session.commit()
    assert client.post(f"/seller/portfolios/{portfolio_id}/status", data={"status": "live"}).status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.Portfolio, portfolio_id).status == "live"


def test_confidential_portfolio_and_listings_are_redacted_for_public(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    client.post(f"/seller/portfolios/{portfolio_id}/status", data={"status": "live"})
    client.post("/logout")
    page = client.get(f"/portfolios/{portfolio_id}")
    assert page.status_code == 200
    assert b"National operator group" not in page.data
    assert b"SECRET BUSINESS NAME" not in page.data
    assert b"Confidential business portfolio" in page.data
    listing_page = client.get("/listings/1")
    assert b"SECRET BUSINESS NAME" not in listing_page.data


def test_premium_buyer_can_enquire_for_whole_portfolio_or_lot(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    with seeded_app.app.app_context():
        lot_id = seeded_app.PortfolioLot.query.one().id
    client.post(f"/seller/portfolios/{portfolio_id}/status", data={"status": "live"})
    client.post("/logout")
    login(client, "buyer")
    page = client.get(f"/portfolios/{portfolio_id}")
    assert b"National operator group" in page.data
    assert b"SECRET BUSINESS NAME" in page.data
    assert client.post(f"/portfolios/{portfolio_id}", data={
        "message": "Interested in the full group", "nda_accepted": "on",
    }).status_code == 302
    assert client.post(f"/portfolios/{portfolio_id}", data={
        "message": "Interested in this lot", "nda_accepted": "on", "lot_id": str(lot_id),
    }).status_code == 302
    with seeded_app.app.app_context():
        enquiries = seeded_app.PortfolioEnquiry.query.order_by(seeded_app.PortfolioEnquiry.id).all()
        assert len(enquiries) == 2
        assert enquiries[0].lot_id is None
        assert enquiries[1].lot_id == lot_id
        assert all(enquiry.nda_accepted for enquiry in enquiries)


def test_portfolio_enquiry_requires_nda_and_premium(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    client.post(f"/seller/portfolios/{portfolio_id}/status", data={"status": "live"})
    client.post("/logout")
    login(client, "buyer")
    response = client.post(
        f"/portfolios/{portfolio_id}", data={"message": "No NDA"}, follow_redirects=True,
    )
    assert b"Confirm the confidentiality undertaking" in response.data
    with seeded_app.app.app_context():
        assert seeded_app.PortfolioEnquiry.query.count() == 0
        seeded_app.Subscription.query.filter_by(user_id=3).one().is_active = False
        seeded_app.db.session.commit()
    response = client.post(
        f"/portfolios/{portfolio_id}",
        data={"message": "Basic buyer", "nda_accepted": "on"},
    )
    assert response.status_code == 302
    assert "/pricing" in response.headers["Location"]


def test_structural_change_returns_live_portfolio_to_draft(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    client.post(f"/seller/portfolios/{portfolio_id}/status", data={"status": "live"})
    with seeded_app.app.app_context():
        lot_id = seeded_app.PortfolioLot.query.one().id
    response = client.post(
        f"/seller/portfolios/{portfolio_id}/lots",
        data={"name": "Southern lot", "asking_price": "2500000"},
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        portfolio = seeded_app.db.session.get(seeded_app.Portfolio, portfolio_id)
        assert portfolio.status == "draft"
        assert len(portfolio.lots) == 2
    assert client.post(
        f"/seller/portfolios/{portfolio_id}/listings/1",
        data={"lot_id": lot_id},
    ).status_code == 302


def test_constituent_listing_status_change_unpublishes_portfolio(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    client.post(f"/seller/portfolios/{portfolio_id}/status", data={"status": "live"})
    response = client.post(
        "/seller/listings/1/status", data={"status": "draft"}, follow_redirects=True,
    )
    assert b"returned to draft" in response.data
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.Portfolio, portfolio_id).status == "draft"
    client.post("/logout")
    assert client.get(f"/portfolios/{portfolio_id}").status_code == 404


def test_database_prevents_duplicate_listing_in_same_portfolio(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    with seeded_app.app.app_context():
        lot = seeded_app.PortfolioLot.query.one()
        seeded_app.db.session.add(seeded_app.PortfolioLotListing(
            portfolio_id=portfolio_id, lot_id=lot.id, listing_id=1,
        ))
        with pytest.raises(IntegrityError):
            seeded_app.db.session.commit()
        seeded_app.db.session.rollback()


def test_other_seller_cannot_manage_portfolio(client, seeded_app):
    portfolio_id = create_portfolio(client, seeded_app)
    with seeded_app.app.app_context():
        user = seeded_app.User(email="seller2@example.test", role="seller", email_verified_at=seeded_app.utcnow())
        user.set_password("Testing123!")
        seeded_app.db.session.add(user)
        seeded_app.db.session.commit()
    client.post("/logout")
    client.post("/login", data={"email": "seller2@example.test", "password": "Testing123!"})
    assert client.get(f"/seller/portfolios/{portfolio_id}/edit").status_code == 404
    assert client.post(f"/seller/portfolios/{portfolio_id}/status", data={"status": "live"}).status_code == 404
