from datetime import timedelta

from conftest import login


def prepare_adviser(app, *slugs):
    with app.app.app_context():
        categories = app.get_adviser_categories()
        profile = app.ValuerProfile.query.filter_by(user_id=4).one()
        app.sync_adviser_services(profile, slugs or ("business-valuation",))
        app.db.session.commit()
        return profile.id, {category.slug: category.id for category in categories}


def create_request(client, profile_id, category_id, **overrides):
    data = {
        "category_id": str(category_id), "listing_id": "1",
        "scope": "Independent review of maintainable earnings and valuation range",
        "budget": "2500.50", "currency": "GBP",
    }
    data.update(overrides)
    return client.post(f"/advisers/{profile_id}/request", data=data)


def test_adviser_profile_categories_availability_and_verification(client, seeded_app):
    prepare_adviser(seeded_app)
    login(client, "valuer")
    response = client.post(
        "/valuer/profile",
        data={
            "company_name": "ValuerCo", "accreditation": "RICS",
            "regions": ["Midlands", "London"],
            "categories": ["business-valuation", "due-diligence"],
            "availability_status": "limited", "remote_service": "1",
            "request_verification": "1", "bio": "Transaction specialist",
        },
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        profile = seeded_app.ValuerProfile.query.filter_by(user_id=4).one()
        assert profile.verification_status == "pending"
        assert profile.availability_status == "limited"
        assert profile.remote_service is True
        assert {service.category.slug for service in profile.adviser_services} == {
            "business-valuation", "due-diligence"
        }
        profile_id = profile.id
    client.post("/logout")
    login(client, "admin")
    assert client.post(
        f"/admin/advisers/{profile_id}/verification", data={"status": "verified"}
    ).status_code == 302
    with seeded_app.app.app_context():
        profile = seeded_app.db.session.get(seeded_app.ValuerProfile, profile_id)
        assert profile.verification_status == "verified"
        assert profile.verified_by_id == 1
        assert seeded_app.AuditEvent.query.filter_by(
            event_type="admin.adviser_verification_updated"
        ).count() == 1


def test_directory_filters_by_discipline_and_does_not_show_contact_email(client, seeded_app):
    prepare_adviser(seeded_app, "due-diligence")
    page = client.get("/advisers?category=due-diligence&region=Midlands")
    assert page.status_code == 200
    assert b"ValuerCo" in page.data
    assert b"Due diligence" in page.data
    assert b"valuer@example.test" not in page.data
    excluded = client.get("/advisers?category=deal-finance")
    assert b"ValuerCo" not in excluded.data


def test_request_quote_accept_complete_and_review_workflow(client, seeded_app):
    profile_id, categories = prepare_adviser(seeded_app)
    login(client, "seller")
    assert create_request(
        client, profile_id, categories["business-valuation"]
    ).status_code == 302
    with seeded_app.app.app_context():
        adviser_request = seeded_app.AdviserRequest.query.one()
        request_id = adviser_request.id
        assert adviser_request.budget_minor == 250050
        assert adviser_request.requester_id == 2
        assert seeded_app.Notification.query.filter_by(
            user_id=4, event_type="adviser_request"
        ).count() == 1

    client.post("/logout")
    login(client, "valuer")
    assert client.post(
        f"/adviser/requests/{request_id}/quote",
        data={
            "fee": "1750.25", "currency": "GBP",
            "scope": "Desktop valuation and written report",
            "terms": "50% on instruction", "valid_until": "2026-12-31",
        },
    ).status_code == 302
    with seeded_app.app.app_context():
        quote = seeded_app.AdviserQuote.query.one()
        quote_id = quote.id
        assert quote.fee_minor == 175025
        assert quote.revision == 1
        assert seeded_app.AdviserRequest.query.one().status == "quoted"

    client.post("/logout")
    login(client, "seller")
    assert client.post(
        f"/adviser/requests/{request_id}/action",
        data={"action": "accept_quote", "quote_id": quote_id},
    ).status_code == 302
    client.post("/logout")
    login(client, "valuer")
    assert client.post(
        f"/adviser/requests/{request_id}/action", data={"action": "complete"}
    ).status_code == 302
    client.post("/logout")
    login(client, "seller")
    assert client.post(
        f"/adviser/requests/{request_id}/review",
        data={"rating": "5", "title": "Clear advice", "body": "Excellent <script>work</script>"},
    ).status_code == 302
    detail = client.get(f"/advisers/{profile_id}")
    assert b"Clear advice" in detail.data
    assert b"Excellent <script>" not in detail.data
    assert b"Excellent &lt;script&gt;" in detail.data
    with seeded_app.app.app_context():
        adviser_request = seeded_app.AdviserRequest.query.one()
        assert adviser_request.status == "completed"
        assert adviser_request.completed_at is not None
        assert seeded_app.AdviserQuote.query.one().status == "accepted"
        assert seeded_app.AdviserReview.query.one().rating == 5


def test_request_references_are_ownership_checked(client, seeded_app):
    profile_id, categories = prepare_adviser(seeded_app)
    login(client, "buyer")
    assert create_request(
        client, profile_id, categories["business-valuation"]
    ).status_code == 404


def test_only_assigned_adviser_can_quote(client, seeded_app):
    profile_id, categories = prepare_adviser(seeded_app)
    login(client, "seller")
    create_request(client, profile_id, categories["business-valuation"])
    with seeded_app.app.app_context():
        request_id = seeded_app.AdviserRequest.query.one().id
    assert client.post(
        f"/adviser/requests/{request_id}/quote",
        data={"fee": "1000", "scope": "Invalid seller quote"},
    ).status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.AdviserQuote.query.count() == 0


def test_expired_quotes_are_deduplicated_by_scheduled_task(client, seeded_app):
    profile_id, categories = prepare_adviser(seeded_app)
    with seeded_app.app.app_context():
        adviser_request = seeded_app.AdviserRequest(
            requester_id=2, adviser_id=4,
            category_id=categories["business-valuation"], listing_id=1,
            scope="Expired quote test", status="quoted",
        )
        seeded_app.db.session.add(adviser_request)
        seeded_app.db.session.flush()
        quote = seeded_app.AdviserQuote(
            request_id=adviser_request.id, adviser_id=4, revision=1,
            fee_minor=100000, currency="GBP", scope="Expired scope",
            valid_until=seeded_app.utcnow().date() - timedelta(days=1),
        )
        seeded_app.db.session.add(quote)
        seeded_app.db.session.commit()
        quote_id = quote.id
    assert client.get("/tasks/send_weekly_digest?token=test-digest-token").status_code == 200
    assert client.get("/tasks/send_weekly_digest?token=test-digest-token").status_code == 200
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.AdviserQuote, quote_id).status == "expired"
        assert seeded_app.AdviserRequest.query.one().status == "requested"
        assert seeded_app.Notification.query.filter_by(
            user_id=2, dedupe_key=f"adviser-quote:{quote_id}:expired"
        ).count() == 1
