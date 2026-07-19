from datetime import timedelta

from conftest import login


def create_intro(app, status="viewing"):
    with app.app.app_context():
        intro = app.Introduction(
            buyer_id=3, seller_id=2, listing_id=1, status=status
        )
        app.db.session.add(intro)
        app.db.session.commit()
        return intro.id


def submit_offer(client, intro_id, amount="1250000.25", **overrides):
    data = {
        "amount": amount,
        "currency": "GBP",
        "terms": "Completion in 30 days",
        "conditions": "Subject to finance and legal due diligence",
    }
    data.update(overrides)
    return client.post(f"/introductions/{intro_id}/workspace/offers", data=data)


def test_only_parties_can_negotiate_and_admin_is_read_only(client, seeded_app):
    intro_id = create_intro(seeded_app)
    login(client, "valuer")
    assert submit_offer(client, intro_id).status_code == 404
    client.post("/logout")
    login(client, "admin")
    assert client.get(f"/introductions/{intro_id}/workspace").status_code == 200
    assert submit_offer(client, intro_id).status_code == 404


def test_offer_uses_exact_minor_units_and_updates_introduction_stage(client, seeded_app):
    intro_id = create_intro(seeded_app)
    login(client, "buyer")
    assert submit_offer(client, intro_id).status_code == 302
    with seeded_app.app.app_context():
        offer = seeded_app.StructuredOffer.query.one()
        assert offer.amount_minor == 125000025
        assert offer.currency == "GBP"
        assert offer.created_by_id == 3
        assert offer.recipient_id == 2
        assert offer.sequence == 1
        intro = seeded_app.db.session.get(seeded_app.Introduction, intro_id)
        assert intro.status == "offer_made"
        assert seeded_app.IntroductionStatusHistory.query.filter_by(
            introduction_id=intro_id, new_status="offer_made"
        ).count() == 1
        assert seeded_app.Notification.query.filter_by(
            user_id=2, event_type="offer_submitted"
        ).count() == 1
        assert seeded_app.AuditEvent.query.filter_by(event_type="offer.submitted").count() == 1


def test_counter_offer_links_history_and_escapes_conditions(client, seeded_app):
    intro_id = create_intro(seeded_app)
    login(client, "buyer")
    submit_offer(client, intro_id)
    with seeded_app.app.app_context():
        first_id = seeded_app.StructuredOffer.query.one().id
    client.post("/logout")
    login(client, "seller")
    response = client.post(
        f"/workspace/offers/{first_id}/respond",
        data={
            "action": "counter", "amount": "1300000", "currency": "GBP",
            "terms": "Revised timing", "conditions": "No <script>alert(1)</script>",
        },
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        offers = seeded_app.StructuredOffer.query.order_by(
            seeded_app.StructuredOffer.sequence
        ).all()
        assert offers[0].status == "countered"
        assert offers[1].parent_offer_id == offers[0].id
        assert offers[1].recipient_id == 3
        assert offers[1].sequence == 2
    page = client.get(f"/introductions/{intro_id}/workspace")
    assert b"No <script>" not in page.data
    assert b"No &lt;script&gt;" in page.data


def test_acceptance_syncs_legacy_fields_and_deal(client, seeded_app):
    intro_id = create_intro(seeded_app)
    login(client, "buyer")
    submit_offer(client, intro_id, amount="987654.32")
    with seeded_app.app.app_context():
        offer_id = seeded_app.StructuredOffer.query.one().id
    client.post("/logout")
    login(client, "seller")
    assert client.post(
        f"/workspace/offers/{offer_id}/respond", data={"action": "accept"}
    ).status_code == 302
    with seeded_app.app.app_context():
        offer = seeded_app.db.session.get(seeded_app.StructuredOffer, offer_id)
        intro = seeded_app.db.session.get(seeded_app.Introduction, intro_id)
        deal = seeded_app.Deal.query.filter_by(introduction_id=intro_id).one()
        assert offer.status == "accepted"
        assert intro.status == "offer_accepted"
        assert intro.offer_amount == "£987,654.32"
        assert intro.offer_terms == "Completion in 30 days"
        assert deal.agreed_price == "£987,654.32"
        assert deal.broker_commission_amount == 1975309
        assert seeded_app.IntroductionStatusHistory.query.filter_by(
            introduction_id=intro_id, new_status="offer_accepted"
        ).count() == 1


def test_only_creator_can_withdraw_and_only_recipient_can_decide(client, seeded_app):
    intro_id = create_intro(seeded_app)
    login(client, "buyer")
    submit_offer(client, intro_id)
    with seeded_app.app.app_context():
        offer_id = seeded_app.StructuredOffer.query.one().id
    assert client.post(
        f"/workspace/offers/{offer_id}/respond", data={"action": "accept"}
    ).status_code == 404
    client.post("/logout")
    login(client, "seller")
    assert client.post(
        f"/workspace/offers/{offer_id}/respond", data={"action": "withdraw"}
    ).status_code == 404
    assert client.post(
        f"/workspace/offers/{offer_id}/respond", data={"action": "reject"}
    ).status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.StructuredOffer, offer_id).status == "rejected"


def test_digest_expires_offers_once_and_expired_offer_cannot_be_accepted(client, seeded_app):
    intro_id = create_intro(seeded_app)
    with seeded_app.app.app_context():
        offer = seeded_app.StructuredOffer(
            introduction_id=intro_id, sequence=1, created_by_id=3, recipient_id=2,
            amount_minor=100000000, currency="GBP", status="submitted",
            expires_on=seeded_app.utcnow().date() - timedelta(days=1),
        )
        seeded_app.db.session.add(offer)
        seeded_app.db.session.commit()
        offer_id = offer.id
    assert client.get("/tasks/send_weekly_digest?token=test-digest-token").status_code == 200
    assert client.get("/tasks/send_weekly_digest?token=test-digest-token").status_code == 200
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.StructuredOffer, offer_id).status == "expired"
        assert seeded_app.Notification.query.filter_by(
            user_id=3, dedupe_key=f"offer:{offer_id}:expired"
        ).count() == 1
    login(client, "seller")
    assert client.post(
        f"/workspace/offers/{offer_id}/respond", data={"action": "accept"}
    ).status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.Deal.query.filter_by(introduction_id=intro_id).count() == 0
