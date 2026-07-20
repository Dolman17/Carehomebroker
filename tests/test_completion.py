import hashlib
import io
import os

from conftest import login


def make_introduction(app, *, status="offer_accepted"):
    with app.app.app_context():
        intro = app.Introduction(
            buyer_id=3, seller_id=2, listing_id=1, status=status,
        )
        app.db.session.add(intro)
        app.db.session.flush()
        deal = app.Deal(introduction_id=intro.id, status="in_progress")
        app.db.session.add(deal)
        app.db.session.commit()
        return intro.id


def test_completion_workspace_is_private_and_admin_is_read_only(client, seeded_app):
    intro_id = make_introduction(seeded_app)
    assert client.get(f"/introductions/{intro_id}/completion").status_code == 302
    login(client, "valuer")
    assert client.get(f"/introductions/{intro_id}/completion").status_code == 404
    client.post("/logout")
    login(client, "admin")
    assert client.get(f"/introductions/{intro_id}/completion").status_code == 200
    assert client.post(f"/introductions/{intro_id}/completion/handover").status_code == 404
    response = client.post(
        f"/admin/introductions/{intro_id}/status",
        data={"status": "completed"}, follow_redirects=True,
    )
    assert b"must be confirmed by both transaction parties" in response.data


def test_assigned_party_controls_checklist_and_condition(client, seeded_app):
    intro_id = make_introduction(seeded_app)
    login(client, "seller")
    assert client.post(f"/introductions/{intro_id}/completion/checklist", data={
        "title": "Funding confirmation", "category": "financial",
        "assigned_to": "buyer", "is_required": "on",
    }).status_code == 302
    assert client.post(f"/introductions/{intro_id}/completion/conditions", data={
        "title": "Regulatory consent", "responsible_party": "buyer",
    }).status_code == 302
    with seeded_app.app.app_context():
        item_id = seeded_app.CompletionChecklistItem.query.one().id
        condition_id = seeded_app.CompletionCondition.query.one().id
    assert client.post(f"/completion/checklist/{item_id}", data={"status": "completed"}).status_code == 404
    assert client.post(f"/completion/conditions/{condition_id}", data={"status": "satisfied"}).status_code == 404
    client.post("/logout")
    login(client, "buyer")
    assert client.post(f"/completion/checklist/{item_id}", data={"status": "completed"}).status_code == 302
    assert client.post(f"/completion/conditions/{condition_id}", data={"status": "satisfied"}).status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.db.session.get(seeded_app.CompletionChecklistItem, item_id).completed_by_id == 3
        assert seeded_app.db.session.get(seeded_app.CompletionCondition, condition_id).resolved_by_id == 3


def test_signature_document_is_private_checksummed_and_requires_each_party(client, seeded_app):
    intro_id = make_introduction(seeded_app)
    content = b"%PDF-1.4\ncompletion test document\n%%EOF"
    login(client, "seller")
    response = client.post(
        f"/introductions/{intro_id}/completion/signature-documents",
        data={
            "title": "Share purchase agreement",
            "document": (io.BytesIO(content), "agreement.pdf"),
            "requires_buyer": "on", "requires_seller": "on", "is_required": "on",
        }, content_type="multipart/form-data",
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        document = seeded_app.SignatureDocument.query.one()
        document_id = document.id
        stored_path = os.path.join(seeded_app.app.config["COMPLETION_DOCS_FOLDER"], document.filename)
        assert document.checksum_sha256 == hashlib.sha256(content).hexdigest()
        assert os.path.isfile(stored_path)
        assert "static" not in stored_path
    download = client.get(f"/completion/signature-documents/{document_id}/download")
    assert download.status_code == 200 and download.data == content
    assert client.post(
        f"/completion/signature-documents/{document_id}/status", data={"action": "sign"}
    ).status_code == 302
    with seeded_app.app.app_context():
        document = seeded_app.db.session.get(seeded_app.SignatureDocument, document_id)
        assert document.seller_signed_at and document.status == "ready"
    client.post("/logout")
    login(client, "buyer")
    client.post(f"/completion/signature-documents/{document_id}/status", data={"action": "sign"})
    with seeded_app.app.app_context():
        document = seeded_app.db.session.get(seeded_app.SignatureDocument, document_id)
        assert document.buyer_signed_at and document.status == "signed"


def test_blockers_prevent_handover_and_new_blocker_resets_confirmation(client, seeded_app):
    intro_id = make_introduction(seeded_app)
    login(client, "buyer")
    assert client.post(f"/introductions/{intro_id}/completion/handover").status_code == 302
    with seeded_app.app.app_context():
        record = seeded_app.CompletionRecord.query.one()
        assert record.buyer_confirmed_at is not None
    assert client.post(f"/introductions/{intro_id}/completion/checklist", data={
        "title": "Final meter readings", "category": "handover",
        "assigned_to": "buyer", "is_required": "on",
    }).status_code == 302
    with seeded_app.app.app_context():
        record = seeded_app.CompletionRecord.query.one()
        item_id = seeded_app.CompletionChecklistItem.query.one().id
        assert record.buyer_confirmed_at is None
    response = client.post(
        f"/introductions/{intro_id}/completion/handover", follow_redirects=True,
    )
    assert b"Clear every required completion blocker" in response.data
    client.post(f"/completion/checklist/{item_id}", data={"status": "completed"})
    assert client.post(f"/introductions/{intro_id}/completion/handover").status_code == 302


def test_two_party_handover_finalises_deal_and_listing(client, seeded_app):
    intro_id = make_introduction(seeded_app)
    login(client, "buyer")
    client.post(f"/introductions/{intro_id}/completion/handover", data={
        "handover_notes": "Keys and records transferred",
    })
    client.post("/logout")
    login(client, "seller")
    response = client.post(f"/introductions/{intro_id}/completion/handover")
    assert response.status_code == 302
    with seeded_app.app.app_context():
        intro = seeded_app.db.session.get(seeded_app.Introduction, intro_id)
        assert intro.status == "completed"
        assert intro.deal.status == "completed" and intro.deal.completion_date
        assert intro.completion_record.completed_at
        assert intro.completion_record.handover_notes == "Keys and records transferred"
        assert seeded_app.db.session.get(seeded_app.Listing, 1).status == "sold"
        assert seeded_app.AuditEvent.query.filter_by(event_type="completion.finalised").count() == 1
    assert client.post(f"/introductions/{intro_id}/completion/checklist", data={
        "title": "Late mutation", "category": "other", "assigned_to": "seller",
    }).status_code == 409


def make_portfolio_enquiry(app):
    with app.app.app_context():
        second = app.Listing(
            seller_id=2, listing_code="CH-0003", title="SECOND BUSINESS",
            status="live", is_confidential=True,
        )
        app.db.session.add(second)
        app.db.session.flush()
        portfolio = app.Portfolio(
            seller_id=2, portfolio_code="PF-0001", title="Group",
            sale_mode="lots", status="live",
        )
        app.db.session.add(portfolio)
        app.db.session.flush()
        first_lot = app.PortfolioLot(portfolio_id=portfolio.id, name="Lot one")
        second_lot = app.PortfolioLot(portfolio_id=portfolio.id, name="Lot two", sort_order=1)
        app.db.session.add_all([first_lot, second_lot])
        app.db.session.flush()
        app.db.session.add_all([
            app.PortfolioLotListing(portfolio_id=portfolio.id, lot_id=first_lot.id, listing_id=1),
            app.PortfolioLotListing(portfolio_id=portfolio.id, lot_id=second_lot.id, listing_id=second.id),
        ])
        enquiry = app.PortfolioEnquiry(
            portfolio_id=portfolio.id, lot_id=first_lot.id, buyer_id=3,
            message="Interested", nda_accepted=True,
        )
        app.db.session.add(enquiry)
        app.db.session.commit()
        return enquiry.id, portfolio.id, first_lot.id, second.id


def test_portfolio_enquiry_becomes_governed_introduction_and_lot_completion(client, seeded_app):
    enquiry_id, portfolio_id, lot_id, other_listing_id = make_portfolio_enquiry(seeded_app)
    login(client, "seller")
    assert client.post(f"/seller/portfolio-enquiries/{enquiry_id}/introduction").status_code == 302
    with seeded_app.app.app_context():
        intro = seeded_app.Introduction.query.one()
        intro_id = intro.id
        assert intro.portfolio_id == portfolio_id
        assert intro.portfolio_lot_id == lot_id
        assert intro.portfolio_enquiry_id == enquiry_id
        assert intro.status == "pending_seller_request"
        assert seeded_app.PortfolioEnquiry.query.one().status == "introduced"
    client.post("/logout")
    login(client, "admin")
    client.post(f"/admin/introduction_requests/{intro_id}/approve")
    with seeded_app.app.app_context():
        intro = seeded_app.db.session.get(seeded_app.Introduction, intro_id)
        intro.status = "offer_accepted"
        seeded_app.db.session.add(seeded_app.Deal(introduction_id=intro.id, status="in_progress"))
        seeded_app.db.session.commit()
    client.post("/logout")
    login(client, "buyer")
    client.post(f"/introductions/{intro_id}/completion/handover")
    client.post("/logout")
    login(client, "seller")
    client.post(f"/introductions/{intro_id}/completion/handover")
    with seeded_app.app.app_context():
        portfolio = seeded_app.db.session.get(seeded_app.Portfolio, portfolio_id)
        assert seeded_app.db.session.get(seeded_app.PortfolioLot, lot_id).is_available is False
        assert seeded_app.db.session.get(seeded_app.Listing, 1).status == "sold"
        assert seeded_app.db.session.get(seeded_app.Listing, other_listing_id).status == "live"
        assert portfolio.status == "draft"
