import pytest

from conftest import login


def test_money_values_are_stored_as_exact_minor_units(seeded_app):
    assert seeded_app.parse_major_units("2500000.99") == 250_000_099
    assert seeded_app.format_minor_units(250_000_099, "GBP") == "£2,500,000.99"
    with pytest.raises(ValueError):
        seeded_app.parse_major_units("£2m")


def test_seller_creates_normalised_sector_listing(client, seeded_app):
    login(client, "seller")
    response = client.post(
        "/seller/listings/new",
        data={
            "title": "Recurring revenue software company",
            "region": "London",
            "sector": "technology-software",
            "attribute_employee_count": "24",
            "attribute_recurring_revenue_percent": "82",
            "attribute_customer_count": "190",
            "asking_price": "3250000.50",
            "annual_revenue": "1800000",
            "annual_ebitda": "540000",
            "currency": "GBP",
            "short_description": "Vertical SaaS acquisition opportunity.",
        },
    )
    assert response.status_code == 302

    with seeded_app.app.app_context():
        listing = seeded_app.Listing.query.filter_by(
            title="Recurring revenue software company"
        ).one()
        assert listing.sector.slug == "technology-software"
        assert listing.care_type == "Technology & Software"
        assert listing.attributes == {
            "employee_count": 24,
            "recurring_revenue_percent": 82,
            "customer_count": 190,
        }
        assert listing.asking_price_minor == 325_000_050
        assert listing.revenue_minor == 180_000_000
        assert listing.ebitda_minor == 54_000_000
        assert listing.guide_price_display == "£3,250,000.50"


def test_marketplace_filters_and_sorts_exact_prices(client, seeded_app):
    with seeded_app.app.app_context():
        sector = seeded_app.resolve_sector("technology-software")
        seller_id = seeded_app.User.query.filter_by(role="seller").one().id
        seeded_app.db.session.add_all(
            [
                seeded_app.Listing(
                    seller_id=seller_id,
                    listing_code="OL-TECH-1",
                    title="LOW PRICE TECH",
                    region="London",
                    sector=sector,
                    care_type=sector.name,
                    asking_price_minor=100_000_000,
                    currency="GBP",
                    status="live",
                    is_confidential=True,
                ),
                seeded_app.Listing(
                    seller_id=seller_id,
                    listing_code="OL-TECH-2",
                    title="HIGH PRICE TECH",
                    region="London",
                    sector=sector,
                    care_type=sector.name,
                    asking_price_minor=300_000_000,
                    currency="GBP",
                    status="live",
                    is_confidential=True,
                ),
            ]
        )
        seeded_app.db.session.commit()

    login(client, "buyer")
    response = client.get(
        "/listings?sector=technology-software&min_price=500000&max_price=3500000&sort=price_high"
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "HIGH PRICE TECH" in body
    assert "LOW PRICE TECH" in body
    assert body.index("HIGH PRICE TECH") < body.index("LOW PRICE TECH")
    assert "SECRET BUSINESS NAME" not in body
