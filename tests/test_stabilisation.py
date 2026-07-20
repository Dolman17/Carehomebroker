from conftest import login


def test_anonymous_listing_responses_do_not_contain_confidential_values(client):
    response = client.get("/listings")
    assert response.status_code == 200
    assert b"SECRET BUSINESS NAME" not in response.data
    assert "£4,000,000".encode() not in response.data

    response = client.get("/listings/1")
    assert response.status_code == 200
    assert b"SECRET BUSINESS NAME" not in response.data
    assert "£4,000,000".encode() not in response.data
    assert b"Sensitive summary" not in response.data
    assert b">92%<" not in response.data


def test_anonymous_user_cannot_open_non_live_listing(client):
    assert client.get("/listings/2").status_code == 404


def test_premium_buyer_gets_full_listing_and_dashboard_state(client):
    login(client, "buyer")
    detail = client.get("/listings/1")
    assert detail.status_code == 200
    assert b"SECRET BUSINESS NAME" in detail.data
    assert "£4,000,000".encode() in detail.data

    dashboard = client.get("/buyer/dashboard")
    assert dashboard.status_code == 200
    assert b"Buyer Premium" in dashboard.data
    assert b"deal-ready" in dashboard.data
    assert b"SECRET BUSINESS NAME" in dashboard.data


def test_broken_get_pages_are_restored(client):
    login(client, "seller")
    assert client.get("/seller/buyers").status_code == 200
    assert client.get("/seller/listings/1/request-valuation").status_code == 200
    client.post("/logout")

    login(client, "admin")
    assert client.get("/admin/introduction_requests").status_code == 200
    client.post("/logout")

    assert client.get("/valuers/1").status_code == 200


def test_admin_directories_render_scalar_profile_data(client):
    login(client, "admin")
    assert b"BuyerCo" in client.get("/admin/buyers").data
    assert b"SellerCo" in client.get("/admin/sellers").data
    assert b"ValuerCo" in client.get("/admin/valuers").data


def test_seller_can_request_introduction_for_premium_buyer(client, seeded_app):
    login(client, "seller")
    response = client.post(
        "/seller/request_introduction/3",
        data={"listing_id": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.Introduction.query.count() == 1


def test_valuer_decline_and_digest_do_not_error(client):
    login(client, "valuer")
    assert client.post("/valuer/requests/1/decline").status_code == 302

    digest = client.get("/tasks/send_weekly_digest?token=test-digest-token")
    assert digest.status_code == 200


def test_introduction_detail_and_deal_work_without_scalar_backref(client, seeded_app):
    with seeded_app.app.app_context():
        intro = seeded_app.Introduction(
            buyer_id=3,
            seller_id=2,
            listing_id=1,
            status="initiated",
        )
        seeded_app.db.session.add(intro)
        seeded_app.db.session.commit()

    login(client, "admin")
    assert client.get("/admin/introductions/1").status_code == 200
    response = client.post(
        "/admin/introductions/1/deal",
        data={"agreed_price": "4000000", "broker_commission_percent": "2"},
    )
    assert response.status_code == 302
    response = client.post(
        "/admin/introductions/1/status",
        data={"status": "failed"},
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        deal = seeded_app.Deal.query.filter_by(introduction_id=1).first()
        assert deal is not None
        assert deal.status == "aborted"


def test_csrf_rejects_state_change_without_token(client, seeded_app):
    seeded_app.app.config["WTF_CSRF_ENABLED"] = True
    response = client.post(
        "/login",
        data={"email": "buyer@example.test", "password": "Testing123!"},
    )
    assert response.status_code == 400


def test_core_route_set_is_preserved_with_legal_pages(seeded_app):
    route_rules = list(seeded_app.app.url_map.iter_rules())
    rules = {rule.rule for rule in route_rules}
    assert "/buyer/dashboard" in rules
    assert "/seller/dashboard" in rules
    assert "/valuer/dashboard" in rules
    assert "/admin" in rules
    assert "/my/dashboard" in rules
    assert len(route_rules) == 171


def test_buyer_shortlist_persists_in_database(client, seeded_app):
    login(client, "buyer")
    response = client.post(
        "/listings/1/toggle-shortlist",
        data={"next": "/buyer/shortlist"},
    )
    assert response.status_code == 302

    with client.session_transaction() as browser_session:
        browser_session.pop("shortlist", None)

    page = client.get("/buyer/shortlist")
    assert page.status_code == 200
    assert b"SECRET BUSINESS NAME" in page.data
    with seeded_app.app.app_context():
        assert seeded_app.ShortlistItem.query.filter_by(
            buyer_id=3, listing_id=1
        ).count() == 1


def test_buyer_can_manage_saved_searches(client, seeded_app):
    login(client, "buyer")
    response = client.post(
        "/buyer/saved-searches",
        data={
            "name": "Midlands residential",
            "search_q": "growth",
            "region": "Midlands",
            "care_type": "Residential",
            "email_alerts": "1",
        },
    )
    assert response.status_code == 302

    page = client.get("/buyer/saved-searches")
    assert b"Midlands residential" in page.data
    with seeded_app.app.app_context():
        saved_search = seeded_app.SavedSearch.query.one()
        assert saved_search.email_alerts is True
        search_id = saved_search.id

    assert client.post(f"/buyer/saved-searches/{search_id}/alerts").status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(
            seeded_app.SavedSearch, search_id
        ).email_alerts is False

    assert client.post(f"/buyer/saved-searches/{search_id}/delete").status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.SavedSearch.query.count() == 0


def test_weekly_digest_includes_opted_in_saved_search_matches(
    client, seeded_app, monkeypatch
):
    sent_messages = []
    monkeypatch.setattr(
        seeded_app,
        "send_email",
        lambda recipient, subject, body: sent_messages.append(
            (recipient, subject, body)
        ) or True,
    )
    with seeded_app.app.app_context():
        seeded_app.db.session.add(
            seeded_app.SavedSearch(
                buyer_id=3,
                name="Midlands opportunities",
                region="Midlands",
                email_alerts=True,
            )
        )
        seeded_app.db.session.commit()

    response = client.get("/tasks/send_weekly_digest?token=test-digest-token")
    assert response.status_code == 200
    assert len(sent_messages) == 1
    assert "Saved search: Midlands opportunities" in sent_messages[0][2]
