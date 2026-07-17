import os
import sys
from pathlib import Path

import pytest


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("DIGEST_TASK_TOKEN", "test-digest-token")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as application


@pytest.fixture()
def seeded_app(monkeypatch):
    application.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SERVER_NAME="localhost",
    )
    monkeypatch.setattr(application, "send_email", lambda *args, **kwargs: True)

    with application.app.app_context():
        application.db.drop_all()
        application.db.create_all()

        users = {}
        for role in ("admin", "seller", "buyer", "valuer"):
            user = application.User(email=f"{role}@example.test", role=role)
            user.set_password("Testing123!")
            application.db.session.add(user)
            users[role] = user

        application.db.session.flush()

        live = application.Listing(
            seller_id=users["seller"].id,
            listing_code="CH-0001",
            title="SECRET BUSINESS NAME",
            region="Midlands",
            care_type="Residential",
            beds=40,
            occupancy_percent=92,
            cqc_rating="Good",
            tenure="Freehold",
            guide_price_band="£4,000,000",
            short_description="Sensitive summary",
            is_confidential=True,
            status="live",
        )
        draft = application.Listing(
            seller_id=users["seller"].id,
            listing_code="CH-0002",
            title="SECRET DRAFT NAME",
            guide_price_band="£9,000,000",
            short_description="Draft secret",
            is_confidential=True,
            status="draft",
        )
        application.db.session.add_all([live, draft])
        application.db.session.flush()

        buyer_profile = application.BuyerProfile(
            user_id=users["buyer"].id,
            business_name="BuyerCo",
            investment_type="acquisition",
            min_budget="£1m",
            max_budget="£10m",
            preferred_regions="Midlands",
            care_types="Residential",
            transaction_timeline="0-3m",
            nda_signed=True,
        )
        seller_profile = application.SellerProfile(
            user_id=users["seller"].id,
            business_name="SellerCo",
            regions="Midlands",
            care_type="Residential",
        )
        valuer_profile = application.ValuerProfile(
            user_id=users["valuer"].id,
            company_name="ValuerCo",
            accreditation="RICS",
            regions="Midlands",
        )
        application.db.session.add_all(
            [buyer_profile, seller_profile, valuer_profile]
        )
        application.db.session.add_all(
            [
                application.Subscription(
                    user_id=users["buyer"].id,
                    role="buyer",
                    tier="premium",
                    is_active=True,
                ),
                application.Subscription(
                    user_id=users["seller"].id,
                    role="seller",
                    tier="premium",
                    is_active=True,
                ),
            ]
        )
        application.db.session.flush()

        valuation = application.ValuationRequest(
            listing_id=live.id,
            seller_id=users["seller"].id,
            valuer_id=users["valuer"].id,
            status="pending",
        )
        application.db.session.add(valuation)
        application.db.session.commit()

    yield application


@pytest.fixture()
def client(seeded_app):
    return seeded_app.app.test_client()


def login(client, role):
    return client.post(
        "/login",
        data={"email": f"{role}@example.test", "password": "Testing123!"},
        follow_redirects=False,
    )
