import pytest
from sqlalchemy.exc import IntegrityError


def test_one_to_one_relationships_are_scalar(seeded_app):
    with seeded_app.app.app_context():
        buyer = seeded_app.db.session.get(seeded_app.User, 3)
        seller = seeded_app.db.session.get(seeded_app.User, 2)
        listing = seeded_app.db.session.get(seeded_app.Listing, 1)

        financials = seeded_app.Financials(listing_id=listing.id)
        criteria = seeded_app.BuyerCriteria(buyer_id=buyer.id)
        introduction = seeded_app.Introduction(
            buyer_id=buyer.id,
            seller_id=seller.id,
            listing_id=listing.id,
        )
        seeded_app.db.session.add_all([financials, criteria, introduction])
        seeded_app.db.session.flush()
        deal = seeded_app.Deal(introduction_id=introduction.id)
        seeded_app.db.session.add(deal)
        seeded_app.db.session.commit()

        assert buyer.buyer_profile.business_name == "BuyerCo"
        assert seller.seller_profile.business_name == "SellerCo"
        assert listing.financials is financials
        assert buyer.criteria is criteria
        assert introduction.deal is deal


def test_database_rejects_duplicate_one_to_one_rows(seeded_app):
    with seeded_app.app.app_context():
        seeded_app.db.session.add_all(
            [
                seeded_app.Financials(listing_id=1),
                seeded_app.Financials(listing_id=1),
            ]
        )

        with pytest.raises(IntegrityError):
            seeded_app.db.session.commit()
        seeded_app.db.session.rollback()


def test_database_rejects_duplicate_introductions(seeded_app):
    with seeded_app.app.app_context():
        values = {"buyer_id": 3, "seller_id": 2, "listing_id": 1}
        seeded_app.db.session.add_all(
            [
                seeded_app.Introduction(**values),
                seeded_app.Introduction(**values),
            ]
        )

        with pytest.raises(IntegrityError):
            seeded_app.db.session.commit()
        seeded_app.db.session.rollback()


def test_admin_seed_requires_explicit_strong_credentials(seeded_app, monkeypatch):
    monkeypatch.delenv("ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)

    with seeded_app.app.app_context():
        with pytest.raises(RuntimeError):
            seeded_app.seed_admin_user()
        with pytest.raises(ValueError):
            seeded_app.seed_admin_user("new-admin@example.test", "weak")
