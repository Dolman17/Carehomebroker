from conftest import login
from test_team_accounts import add_user, make_team


def verify_seeded_buyer(app):
    with app.app.app_context():
        qualification = app.BuyerQualification.query.filter_by(user_id=3).first()
        if not qualification:
            qualification = app.BuyerQualification(user_id=3)
            app.db.session.add(qualification)
        qualification.legal_name = "BuyerCo Limited"
        qualification.identity_status = "verified"
        qualification.business_status = "verified"
        qualification.funds_status = "verified"
        qualification.funds_filename = "evidence.pdf"
        app.db.session.commit()


def test_mandate_submission_requires_verified_buyer(client, seeded_app):
    with seeded_app.app.app_context():
        seeded_app.BuyerMandateReview.query.delete()
        seeded_app.db.session.commit()
    login(client, "buyer")
    response = client.post("/buyer/mandate")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/buyer/qualification")
    with seeded_app.app.app_context():
        assert seeded_app.BuyerMandateReview.query.count() == 0


def test_admin_approves_current_snapshot_and_stale_snapshot_is_blocked(client, seeded_app):
    verify_seeded_buyer(seeded_app)
    with seeded_app.app.app_context():
        seeded_app.BuyerMandateReview.query.delete()
        seeded_app.db.session.commit()
    login(client, "buyer")
    assert client.post("/buyer/mandate").status_code == 302
    with seeded_app.app.app_context():
        review = seeded_app.BuyerMandateReview.query.one()
        review_id = review.id
        assert review.status == "pending"
    client.post("/logout")
    login(client, "admin")
    assert client.post(
        f"/admin/buyer-mandates/{review_id}",
        data={"decision": "approved", "review_notes": "Clear acquisition criteria."},
    ).status_code == 302
    with seeded_app.app.app_context():
        review = seeded_app.db.session.get(seeded_app.BuyerMandateReview, review_id)
        assert review.status == "approved"
        review.status = "pending"
        review.buyer_profile.max_budget = "£12m"
        seeded_app.db.session.commit()
    stale = client.post(
        f"/admin/buyer-mandates/{review_id}",
        data={"decision": "approved"}, follow_redirects=True,
    )
    assert b"profile changed after submission" in stale.data


def test_unapproved_mandate_blocks_enquiry_without_blocking_browsing(client, seeded_app):
    with seeded_app.app.app_context():
        review = seeded_app.BuyerMandateReview.query.one()
        review.status = "changes_required"
        seeded_app.db.session.commit()
    login(client, "buyer")
    assert client.get("/listings/1").status_code == 200
    response = client.post("/listings/1", data={"message": "Interested", "nda_accepted": "on"})
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/buyer/mandate")
    with seeded_app.app.app_context():
        assert seeded_app.Enquiry.query.count() == 0


def test_team_premium_requires_selected_workspace_and_assigned_seat(client, seeded_app):
    second_id = add_user(seeded_app, "buyer2@example.test", "buyer")
    team_id = make_team(seeded_app, 3, team_type="buyer", name="Acquisition group")
    with seeded_app.app.app_context():
        owner = seeded_app.TeamMembership.query.filter_by(team_id=team_id, user_id=3).one()
        owner.uses_billing_seat = True
        seeded_app.db.session.add_all([
            seeded_app.TeamMembership(
                team_id=team_id, user_id=second_id, role="contributor",
                status="active", uses_billing_seat=False,
            ),
            seeded_app.Subscription(
                user_id=3, team_id=team_id, role="buyer", tier="premium",
                seat_limit=2, is_active=True,
            ),
        ])
        seeded_app.db.session.commit()
        membership_id = seeded_app.TeamMembership.query.filter_by(
            team_id=team_id, user_id=second_id
        ).one().id
    client.post("/login", data={"email": "buyer2@example.test", "password": "Testing123!"})
    client.post(f"/teams/{team_id}/activate")
    assert client.get("/buyer/matches/1").headers["Location"].endswith("/pricing")
    client.post("/logout")
    login(client, "buyer")
    client.post(
        f"/teams/{team_id}/members/{membership_id}/billing-seat",
        data={"action": "assign"},
    )
    client.post("/logout")
    client.post("/login", data={"email": "buyer2@example.test", "password": "Testing123!"})
    client.post(f"/teams/{team_id}/activate")
    entitled = client.get("/buyer/matches/1")
    assert entitled.status_code == 302
    assert entitled.headers["Location"].endswith("/buyer/profile")
    client.post("/teams/deactivate")
    response = client.get("/buyer/matches/1")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/pricing")


def test_only_team_owner_can_checkout_and_quantity_becomes_seats(client, seeded_app, monkeypatch):
    team_id = make_team(seeded_app, 3, team_type="buyer", name="Acquisition group")
    captured = {}
    monkeypatch.setattr(
        seeded_app.stripe.checkout.Session, "create",
        lambda **kwargs: captured.update(kwargs) or type("Checkout", (), {"url": "https://checkout.stripe.test/team"})(),
    )
    seeded_app.stripe.api_key = "sk_test"
    seeded_app.STRIPE_PRICE_MAP[("buyer", "premium")] = "price_team"
    login(client, "buyer")
    response = client.post(
        "/billing/checkout",
        data={"role": "buyer", "tier": "premium", "team_id": team_id, "seats": 4},
    )
    assert response.status_code == 303
    assert captured["line_items"] == [{"price": "price_team", "quantity": 4}]
    assert captured["metadata"]["team_id"] == str(team_id)
    assert captured["metadata"]["seat_limit"] == "4"
