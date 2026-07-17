from io import BytesIO

from conftest import login


def submit_qualification(client, content_type="application/pdf"):
    return client.post(
        "/buyer/qualification",
        data={
            "legal_name": "Buyer Acquisition Ltd",
            "company_number": "12345678",
            "website": "https://buyer.example",
            "acquisitions_completed": "3",
            "track_record_summary": "Three completed owner-managed business acquisitions.",
            "funds_evidence": (BytesIO(b"private funding letter"), "funding.pdf", content_type),
        },
        content_type="multipart/form-data",
    )


def test_buyer_submits_private_qualification_evidence(client, seeded_app, tmp_path):
    seeded_app.app.config["BUYER_EVIDENCE_FOLDER"] = str(tmp_path)
    login(client, "buyer")
    response = submit_qualification(client)
    assert response.status_code == 302
    with seeded_app.app.app_context():
        qualification = seeded_app.BuyerQualification.query.filter_by(user_id=3).one()
        assert qualification.identity_status == "pending"
        assert qualification.business_status == "pending"
        assert qualification.funds_status == "pending"
        assert qualification.acquisitions_completed == 3
        assert qualification.funds_filename != "funding.pdf"
        assert seeded_app.AuditEvent.query.filter_by(
            event_type="buyer.qualification_submitted"
        ).count() == 1
    evidence = client.get("/buyer/qualification/evidence")
    assert evidence.status_code == 200
    assert evidence.data == b"private funding letter"


def test_admin_review_creates_verified_badges_and_buyer_notification(
    client, seeded_app, tmp_path
):
    seeded_app.app.config["BUYER_EVIDENCE_FOLDER"] = str(tmp_path)
    login(client, "buyer")
    submit_qualification(client)
    client.post("/logout")
    login(client, "admin")
    response = client.post(
        "/admin/buyer-verifications/3",
        data={
            "identity_status": "verified",
            "business_status": "verified",
            "funds_status": "verified",
            "review_notes": "Evidence reviewed.",
        },
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        qualification = seeded_app.BuyerQualification.query.filter_by(user_id=3).one()
        assert qualification.overall_status == "verified"
        assert qualification.reviewed_by_id == 1
        assert seeded_app.Notification.query.filter_by(
            user_id=3, event_type="buyer_qualification"
        ).count() == 1
        assert seeded_app.AuditEvent.query.filter_by(
            event_type="admin.buyer_qualification_reviewed"
        ).count() == 1

    client.post("/logout")
    login(client, "seller")
    matches = client.get("/seller/buyers")
    assert b"Identity verified" in matches.data
    assert b"Business verified" in matches.data
    assert b"Funds verified" in matches.data
    assert b"funding.pdf" not in matches.data


def test_funds_cannot_be_verified_without_evidence(client, seeded_app):
    with seeded_app.app.app_context():
        seeded_app.db.session.add(
            seeded_app.BuyerQualification(
                user_id=3, legal_name="Buyer", identity_status="pending",
                business_status="pending", funds_status="not_submitted",
            )
        )
        seeded_app.db.session.commit()
    login(client, "admin")
    client.post(
        "/admin/buyer-verifications/3",
        data={
            "identity_status": "verified",
            "business_status": "verified",
            "funds_status": "verified",
        },
    )
    with seeded_app.app.app_context():
        assert seeded_app.BuyerQualification.query.one().funds_status == "not_submitted"


def test_evidence_rejects_disguised_files_and_is_not_seller_accessible(
    client, seeded_app, tmp_path
):
    seeded_app.app.config["BUYER_EVIDENCE_FOLDER"] = str(tmp_path)
    login(client, "buyer")
    assert submit_qualification(client, "text/plain").status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.BuyerQualification.query.count() == 0

    client.post("/logout")
    login(client, "seller")
    assert client.get("/admin/buyer-verifications/3/evidence").status_code == 302
    assert client.get("/buyer/qualification/evidence").status_code == 302
