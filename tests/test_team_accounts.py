import hashlib
from datetime import timedelta

from conftest import login


def add_user(app, email, role):
    with app.app.app_context():
        user = app.User(email=email, role=role, email_verified_at=app.utcnow())
        user.set_password("Testing123!")
        app.db.session.add(user)
        app.db.session.commit()
        return user.id


def make_team(app, owner_id, team_type="seller", name="Deal team"):
    with app.app.app_context():
        team = app.Team(name=name, team_type=team_type, created_by_id=owner_id)
        app.db.session.add(team)
        app.db.session.flush()
        app.db.session.add(app.TeamMembership(
            team_id=team.id, user_id=owner_id, role="owner", status="active"
        ))
        app.db.session.commit()
        return team.id


def test_team_creation_uses_account_type_and_audits(client, seeded_app):
    login(client, "seller")
    response = client.post("/teams", data={"name": "Seller advisory team"})
    assert response.status_code == 302
    with seeded_app.app.app_context():
        team = seeded_app.Team.query.one()
        membership = seeded_app.TeamMembership.query.one()
        assert team.team_type == "seller"
        assert membership.role == "owner"
        assert seeded_app.AuditEvent.query.filter_by(event_type="team.created").count() == 1


def test_invitation_is_role_compatible_hashed_and_email_bound(client, seeded_app):
    team_id = make_team(seeded_app, 2)
    login(client, "seller")
    # Admin accounts cannot be invited into a seller team.
    response = client.post(
        f"/teams/{team_id}/invite",
        data={"email": "admin@example.test", "role": "manager"},
        follow_redirects=True,
    )
    assert b"not compatible" in response.data
    with seeded_app.app.app_context():
        assert seeded_app.TeamInvitation.query.count() == 0
        raw_token = "invitation-secret-token"
        invitation = seeded_app.TeamInvitation(
            team_id=team_id, email="valuer@example.test", role="contributor",
            token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
            invited_by_id=2, expires_at=seeded_app.utcnow() + timedelta(days=7),
        )
        seeded_app.db.session.add(invitation)
        seeded_app.db.session.commit()
    # A different signed-in account cannot consume the link.
    assert client.get(f"/teams/invitations/{raw_token}").status_code == 403
    client.post("/logout")
    login(client, "valuer")
    assert client.post(f"/teams/invitations/{raw_token}").status_code == 302
    assert client.get("/teams").status_code == 200
    with seeded_app.app.app_context():
        membership = seeded_app.TeamMembership.query.filter_by(user_id=4).one()
        assert membership.role == "contributor"
        assert seeded_app.db.session.get(seeded_app.User, 4).role == "valuer"


def test_seller_team_permissions_protect_shared_listing(client, seeded_app):
    team_id = make_team(seeded_app, 2)
    with seeded_app.app.app_context():
        listing = seeded_app.db.session.get(seeded_app.Listing, 1)
        listing.team_id = team_id
        seeded_app.db.session.add_all([
            seeded_app.TeamMembership(team_id=team_id, user_id=4, role="viewer"),
        ])
        seeded_app.db.session.commit()
    login(client, "valuer")
    assert client.get("/seller/listings/1/edit").status_code == 302
    team_page = client.get(f"/teams/{team_id}")
    assert team_page.status_code == 200
    assert b"SECRET BUSINESS NAME" in team_page.data
    with seeded_app.app.app_context():
        seeded_app.TeamMembership.query.filter_by(user_id=4).one().role = "contributor"
        seeded_app.db.session.commit()
    assert client.get("/seller/listings/1/edit").status_code == 200
    assert client.get("/seller/listings/1/data-room").status_code == 200


def test_buyer_team_shares_shortlist_and_saved_searches(client, seeded_app):
    second_id = add_user(seeded_app, "buyer2@example.test", "buyer")
    team_id = make_team(seeded_app, 3, team_type="buyer", name="Acquisition group")
    with seeded_app.app.app_context():
        seeded_app.db.session.add(seeded_app.TeamMembership(
            team_id=team_id, user_id=second_id, role="contributor"
        ))
        seeded_app.db.session.commit()
    login(client, "buyer")
    client.post(f"/teams/{team_id}/activate")
    assert client.post("/listings/1/toggle-shortlist").status_code == 302
    assert client.post("/buyer/saved-searches", data={"name": "Shared Midlands", "region": "Midlands"}).status_code == 302
    client.post("/logout")
    client.post("/login", data={"email": "buyer2@example.test", "password": "Testing123!"})
    client.post(f"/teams/{team_id}/activate")
    assert b"CH-0001" in client.get("/buyer/shortlist").data
    assert b"SECRET BUSINESS NAME" not in client.get("/buyer/shortlist").data
    assert b"Shared Midlands" in client.get("/buyer/saved-searches").data


def test_viewer_cannot_change_shared_buyer_resources(client, seeded_app):
    second_id = add_user(seeded_app, "buyer2@example.test", "buyer")
    team_id = make_team(seeded_app, 3, team_type="buyer")
    with seeded_app.app.app_context():
        seeded_app.db.session.add(seeded_app.TeamMembership(
            team_id=team_id, user_id=second_id, role="viewer"
        ))
        seeded_app.db.session.commit()
    client.post("/login", data={"email": "buyer2@example.test", "password": "Testing123!"})
    client.post(f"/teams/{team_id}/activate")
    assert client.post("/listings/1/toggle-shortlist").status_code == 403
    assert client.post("/buyer/saved-searches", data={"name": "Not allowed"}).status_code == 403


def test_personal_and_team_shortlists_remain_separate(client, seeded_app):
    team_id = make_team(seeded_app, 3, team_type="buyer")
    login(client, "buyer")
    assert client.post("/listings/1/toggle-shortlist").status_code == 302
    assert client.post(f"/teams/{team_id}/activate").status_code == 302
    assert client.post("/listings/1/toggle-shortlist").status_code == 302
    with seeded_app.app.app_context():
        rows = seeded_app.ShortlistItem.query.filter_by(buyer_id=3, listing_id=1).all()
        assert len(rows) == 2
        assert {row.team_id for row in rows} == {None, team_id}


def test_team_owner_cannot_be_removed_or_demoted(client, seeded_app):
    team_id = make_team(seeded_app, 2)
    with seeded_app.app.app_context():
        owner_membership_id = seeded_app.TeamMembership.query.one().id
    login(client, "seller")
    response = client.post(
        f"/teams/{team_id}/members/{owner_membership_id}",
        data={"action": "remove"}, follow_redirects=True,
    )
    assert b"owner cannot be changed or removed" in response.data
    with seeded_app.app.app_context():
        membership = seeded_app.TeamMembership.query.one()
        assert membership.role == "owner" and membership.status == "active"
