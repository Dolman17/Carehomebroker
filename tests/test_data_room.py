from io import BytesIO

from conftest import login


def create_introduction(app):
    with app.app.app_context():
        intro = app.Introduction(
            buyer_id=3, seller_id=2, listing_id=1, status="initiated"
        )
        app.db.session.add(intro)
        app.db.session.commit()
        return intro.id


def upload_document(client, title, stage, filename="document.pdf", replacement_id=None):
    data = {
        "title": title,
        "category": "financial" if stage == "nda" else "legal",
        "disclosure_stage": stage,
        "document": (BytesIO(f"contents for {title}".encode()), filename),
    }
    if replacement_id:
        data["replacement_id"] = str(replacement_id)
    return client.post(
        "/seller/listings/1/data-room",
        data=data,
        content_type="multipart/form-data",
    )


def test_disclosure_stage_controls_buyer_visibility_and_downloads(
    client, seeded_app, tmp_path
):
    seeded_app.app.config["DATA_ROOM_FOLDER"] = str(tmp_path)
    intro_id = create_introduction(seeded_app)
    login(client, "seller")
    assert upload_document(client, "Management accounts", "nda").status_code == 302
    assert upload_document(client, "Legal contracts", "due_diligence").status_code == 302

    with seeded_app.app.app_context():
        accounts = seeded_app.DataRoomDocument.query.filter_by(
            title="Management accounts"
        ).one()
        legal = seeded_app.DataRoomDocument.query.filter_by(title="Legal contracts").one()
        accounts_id, legal_id = accounts.id, legal.id

    client.post("/logout")
    login(client, "buyer")
    locked = client.get(f"/introductions/{intro_id}/data-room")
    assert b"Access has not been granted" in locked.data
    assert client.get(f"/data-room/documents/{accounts_id}/download").status_code == 404

    client.post("/logout")
    login(client, "seller")
    assert client.post(
        f"/introductions/{intro_id}/data-room/access",
        data={"disclosure_stage": "nda"},
    ).status_code == 302

    client.post("/logout")
    login(client, "buyer")
    room = client.get(f"/introductions/{intro_id}/data-room")
    assert b"Management accounts" in room.data
    assert b"Legal contracts" not in room.data
    assert client.get(f"/data-room/documents/{accounts_id}/download").status_code == 200
    assert client.get(f"/data-room/documents/{legal_id}/download").status_code == 404

    with seeded_app.app.app_context():
        assert seeded_app.AuditEvent.query.filter_by(
            event_type="data_room.document_downloaded",
            resource_id=str(accounts_id),
        ).count() == 1


def test_access_revocation_is_immediate_and_notifies_buyer(client, seeded_app, tmp_path):
    seeded_app.app.config["DATA_ROOM_FOLDER"] = str(tmp_path)
    intro_id = create_introduction(seeded_app)
    login(client, "seller")
    upload_document(client, "Accounts", "nda")
    client.post(
        f"/introductions/{intro_id}/data-room/access",
        data={"disclosure_stage": "nda"},
    )
    assert client.post(
        f"/introductions/{intro_id}/data-room/access",
        data={"disclosure_stage": "revoked"},
    ).status_code == 302

    client.post("/logout")
    login(client, "buyer")
    room = client.get(f"/introductions/{intro_id}/data-room")
    assert b"Access has not been granted" in room.data
    with seeded_app.app.app_context():
        access = seeded_app.DataRoomAccess.query.filter_by(
            introduction_id=intro_id
        ).one()
        assert access.revoked_at is not None
        assert seeded_app.Notification.query.filter_by(
            user_id=3, event_type="data_room_access"
        ).count() == 2


def test_replacement_retains_versions_and_archive_is_soft(client, seeded_app, tmp_path):
    seeded_app.app.config["DATA_ROOM_FOLDER"] = str(tmp_path)
    login(client, "seller")
    upload_document(client, "Accounts", "nda", "accounts-2025.pdf")
    with seeded_app.app.app_context():
        first = seeded_app.DataRoomDocument.query.one()
        first_id, key = first.id, first.document_key

    assert upload_document(
        client, "Accounts updated", "nda", "accounts-2026.pdf", first_id
    ).status_code == 302
    with seeded_app.app.app_context():
        versions = seeded_app.DataRoomDocument.query.filter_by(
            document_key=key
        ).order_by(seeded_app.DataRoomDocument.version).all()
        assert [item.version for item in versions] == [1, 2]
        assert versions[0].is_current is False
        assert versions[1].is_current is True
        latest_id = versions[1].id

    assert client.post(f"/data-room/documents/{latest_id}/archive").status_code == 302
    with seeded_app.app.app_context():
        archived = seeded_app.db.session.get(seeded_app.DataRoomDocument, latest_id)
        assert archived.archived_at is not None
        assert archived.is_current is False
        assert seeded_app.DataRoomDocument.query.filter_by(document_key=key).count() == 2


def test_unrelated_users_cannot_open_an_introduction_data_room(client, seeded_app):
    intro_id = create_introduction(seeded_app)
    login(client, "valuer")
    assert client.get(f"/introductions/{intro_id}/data-room").status_code == 404


def test_upload_rejects_disguised_file_type(client, seeded_app, tmp_path):
    seeded_app.app.config["DATA_ROOM_FOLDER"] = str(tmp_path)
    login(client, "seller")
    response = client.post(
        "/seller/listings/1/data-room",
        data={
            "category": "financial",
            "disclosure_stage": "nda",
            "document": (BytesIO(b"not a pdf"), "accounts.pdf", "text/plain"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.DataRoomDocument.query.count() == 0


def test_pending_introduction_cannot_receive_access(client, seeded_app):
    with seeded_app.app.app_context():
        intro = seeded_app.Introduction(
            buyer_id=3, seller_id=2, listing_id=1, status="pending_seller_request"
        )
        seeded_app.db.session.add(intro)
        seeded_app.db.session.commit()
        intro_id = intro.id
    login(client, "seller")
    response = client.post(
        f"/introductions/{intro_id}/data-room/access",
        data={"disclosure_stage": "nda"},
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.DataRoomAccess.query.count() == 0
