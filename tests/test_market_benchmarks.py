from datetime import timedelta

from conftest import login


def completed_deal(app):
    with app.app.app_context():
        sector = app.Sector(name="Healthcare", slug="healthcare", is_active=True)
        app.db.session.add(sector)
        listing = app.db.session.get(app.Listing, 1)
        listing.sector = sector
        listing.region = "Midlands"
        listing.currency = "GBP"
        listing.revenue_minor = 200_000_000
        listing.ebitda_minor = 50_000_000
        intro = app.Introduction(buyer_id=3, seller_id=2, listing_id=1, status="completed")
        app.db.session.add(intro)
        app.db.session.flush()
        deal = app.Deal(
            introduction_id=intro.id, status="completed", agreed_price="£3,000,000",
            completion_date=app.utcnow(),
        )
        app.db.session.add(deal)
        app.db.session.commit()
        return deal.id, intro.id, sector.id


def add_records(app, sector_id, count=5, financials=True):
    with app.app.app_context():
        admin_id = app.User.query.filter_by(role="admin").one().id
        for index in range(count):
            # Internal source deals are required, but never exposed by the insights route.
            listing = app.Listing(
                seller_id=2, listing_code=f"BM-{app.Listing.query.count() + 1:04d}",
                title=f"Private benchmark source {index}", status="sold",
                sector_id=sector_id, region="Midlands", currency="GBP",
            )
            app.db.session.add(listing)
            app.db.session.flush()
            intro = app.Introduction(buyer_id=3, seller_id=2, listing_id=listing.id, status="completed")
            app.db.session.add(intro)
            app.db.session.flush()
            deal = app.Deal(introduction_id=intro.id, status="completed", completion_date=app.utcnow())
            app.db.session.add(deal)
            app.db.session.flush()
            app.db.session.add(app.BenchmarkRecord(
                source_deal_id=deal.id, sector_id=sector_id, region="Midlands",
                completed_on=app.utcnow().date() - timedelta(days=index * 30),
                price_minor=(2_000_000 + index * 100_000) * 100,
                revenue_minor=100_000_000 if financials else None,
                ebitda_minor=25_000_000 if financials else None,
                currency="GBP", published_by_id=admin_id,
            ))
        app.db.session.commit()


def test_both_parties_must_consent_and_revocation_withdraws_record(client, seeded_app):
    deal_id, intro_id, _ = completed_deal(seeded_app)
    login(client, "buyer")
    assert client.post(f"/deals/{deal_id}/benchmark-consent", data={"action": "grant"}).status_code == 302
    client.post("/logout")
    login(client, "admin")
    response = client.post(f"/admin/benchmarks/deals/{deal_id}/publish", follow_redirects=True)
    assert b"Both transaction parties" in response.data
    client.post("/logout")
    login(client, "seller")
    client.post(f"/deals/{deal_id}/benchmark-consent", data={"action": "grant"})
    client.post("/logout")
    login(client, "admin")
    assert client.post(f"/admin/benchmarks/deals/{deal_id}/publish").status_code == 302
    with seeded_app.app.app_context():
        record = seeded_app.BenchmarkRecord.query.filter_by(source_deal_id=deal_id).one()
        assert record.price_minor == 300_000_000
        assert record.is_active is True
    client.post("/logout")
    login(client, "buyer")
    client.post(f"/deals/{deal_id}/benchmark-consent", data={"action": "revoke"})
    with seeded_app.app.app_context():
        assert seeded_app.BenchmarkRecord.query.filter_by(source_deal_id=deal_id).one().is_active is False


def test_consent_is_private_to_completed_deal_parties(client, seeded_app):
    deal_id, _, _ = completed_deal(seeded_app)
    login(client, "valuer")
    assert client.post(f"/deals/{deal_id}/benchmark-consent", data={"action": "grant"}).status_code == 404


def test_insights_suppress_small_cohorts_and_never_show_individual_rows(client, seeded_app):
    _, _, sector_id = completed_deal(seeded_app)
    login(client, "buyer")
    add_records(seeded_app, sector_id, count=4)
    page = client.get(f"/market-insights?sector_id={sector_id}")
    assert b"Results protected" in page.data
    assert b"Lower quartile" not in page.data
    add_records(seeded_app, sector_id, count=1)
    page = client.get(f"/market-insights?sector_id={sector_id}")
    assert b"Lower quartile" in page.data
    assert b"SECRET BUSINESS NAME" not in page.data
    assert b"buyer@example.test" not in page.data


def test_seller_report_is_saved_and_private(client, seeded_app):
    _, _, sector_id = completed_deal(seeded_app)
    add_records(seeded_app, sector_id, count=5)
    login(client, "seller")
    response = client.post("/seller/listings/1/benchmark-report", data={"period": "5"})
    assert response.status_code == 302
    with seeded_app.app.app_context():
        report = seeded_app.BenchmarkReport.query.one()
        assert report.method == "ebitda_multiple"
        assert report.sample_size == 5
        report_id = report.id
    client.post("/logout")
    login(client, "buyer")
    assert client.get(f"/benchmark-reports/{report_id}").status_code == 404
    client.post("/logout")
    login(client, "seller")
    page = client.get(f"/benchmark-reports/{report_id}")
    assert page.status_code == 200
    assert b"Not a formal valuation" in page.data
