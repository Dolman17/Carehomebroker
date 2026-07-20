import base64
import hashlib
import io

from conftest import login
import signable_client
from signable_client import DownloadedFile, SignableAPIError, SignableClient
from test_completion import make_introduction


SIGNED_BYTES = b"%PDF-1.7\nsigned by both parties\n%%EOF"


def test_signable_client_uses_basic_auth_and_base64_upload(monkeypatch):
    captured = {}

    class Response:
        status_code = 202

        @staticmethod
        def json():
            return {"envelope_fingerprint": "provider-id"}

    def fake_request(method, url, **kwargs):
        captured.update(method=method, url=url, **kwargs)
        return Response()

    monkeypatch.setattr(signable_client.requests, "request", fake_request)
    client = SignableClient("private-test-key")
    client.send_document(
        title="Agreement",
        filename="agreement.pdf",
        content=b"private document",
        signers=[{"party_name": "Buyer", "party_email": "buyer@example.test", "party_role": "buyer"}],
        metadata={"ownerlane_document_id": "42"},
    )
    assert captured["method"] == "POST"
    assert captured["url"] == "https://api.signable.co.uk/v1/envelopes"
    assert captured["auth"] == ("private-test-key", "x")
    assert captured["allow_redirects"] is False
    assert captured["json"]["envelope_documents"][0]["document_file_content"] == base64.b64encode(b"private document").decode()


def test_signable_client_rejects_untrusted_signed_document_url():
    try:
        SignableClient.download_signed_file("https://attacker.example/signed.pdf")
    except SignableAPIError as exc:
        assert "unsafe document URL" in str(exc)
    else:
        raise AssertionError("An untrusted signed-document host was accepted")


class FakeSignable:
    def __init__(self):
        self.sent = []
        self.cancelled = []
        self.status = "sent"

    def send_document(self, **kwargs):
        self.sent.append(kwargs)
        return {
            "envelope_fingerprint": "env-ownerlane-1",
            "envelope_queued": "2026-07-20T10:00:00Z",
        }

    def get_envelope(self, fingerprint):
        parties = [
            {"party_id": "party-buyer", "contact_email": "buyer@example.test", "party_status": "signed" if self.status == "signed" else "pending"},
            {"party_id": "party-seller", "contact_email": "seller@example.test", "party_status": "signed" if self.status == "signed" else "pending"},
        ]
        return {
            "envelope_fingerprint": fingerprint,
            "envelope_status": self.status,
            "envelope_sent": "2026-07-20T10:00:00Z",
            "envelope_meta": {"ownerlane_document_id": "1"},
            "envelope_parties": parties,
            "envelope_signed_pdf": "https://api.signable.co.uk/signed/test.pdf" if self.status == "signed" else None,
        }

    def signed_download_url(self, data):
        return data.get("envelope_signed_pdf")

    def download_signed_file(self, url):
        return DownloadedFile(SIGNED_BYTES, "application/pdf", ".pdf")

    def cancel_envelope(self, fingerprint):
        self.cancelled.append(fingerprint)
        return {"envelope_fingerprint": fingerprint, "envelope_status": "cancelled"}


def configure_signable(app, fake, monkeypatch):
    app.app.config.update(
        SIGNABLE_API_KEY="test-api-key",
        SIGNABLE_WEBHOOK_USERNAME="ownerlane-hook",
        SIGNABLE_WEBHOOK_PASSWORD="strong-test-secret",
        SIGNABLE_ENABLED=True,
    )
    monkeypatch.setattr(app, "get_signable_client", lambda: fake)


def upload_document(client, intro_id):
    response = client.post(
        f"/introductions/{intro_id}/completion/signature-documents",
        data={
            "title": "Share purchase agreement",
            "document": (io.BytesIO(b"%PDF-1.4\n{signature:buyer:Buyer+signature}\n{signature:seller:Seller+signature}\n%%EOF"), "agreement.pdf"),
            "requires_buyer": "on",
            "requires_seller": "on",
            "is_required": "on",
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 302


def test_send_creates_provider_envelope_without_exposing_private_file(client, seeded_app, monkeypatch):
    intro_id = make_introduction(seeded_app)
    fake = FakeSignable()
    configure_signable(seeded_app, fake, monkeypatch)
    login(client, "seller")
    upload_document(client, intro_id)

    response = client.post(
        "/completion/signature-documents/1/signable/send",
        data={"confirm_tags": "on"},
    )
    assert response.status_code == 302
    assert len(fake.sent) == 1
    request_data = fake.sent[0]
    assert request_data["metadata"] == {
        "ownerlane_document_id": "1",
        "ownerlane_introduction_id": str(intro_id),
    }
    assert {party["party_role"] for party in request_data["signers"]} == {"buyer", "seller"}
    assert b"{signature:buyer" in request_data["content"]
    assert "url" not in request_data and "document_url" not in request_data

    with seeded_app.app.app_context():
        envelope = seeded_app.ESignatureEnvelope.query.one()
        assert envelope.provider_envelope_id == "env-ownerlane-1"
        assert envelope.status == "processing"
        assert envelope.request_attempts == 1
        assert {party.party_role for party in envelope.parties} == {"buyer", "seller"}
        assert seeded_app.SignatureDocument.query.one().status == "ready"


def test_webhook_requires_auth_and_reconciles_with_provider(client, seeded_app, monkeypatch):
    intro_id = make_introduction(seeded_app)
    fake = FakeSignable()
    configure_signable(seeded_app, fake, monkeypatch)
    login(client, "seller")
    upload_document(client, intro_id)
    client.post("/completion/signature-documents/1/signable/send", data={"confirm_tags": "on"})
    client.post("/logout")

    assert client.post("/webhooks/signable", data={"envelope_fingerprint": "env-ownerlane-1"}).status_code == 401
    fake.status = "signed"
    auth = base64.b64encode(b"ownerlane-hook:strong-test-secret").decode()
    headers = {"Authorization": f"Basic {auth}"}
    payload = {
        "envelope_fingerprint": "env-ownerlane-1",
        "action": "signed-envelope-complete",
        "action_date": "2026-07-20T11:00:00Z",
    }
    assert client.post("/webhooks/signable", data=payload, headers=headers).status_code == 200
    assert client.post("/webhooks/signable", data=payload, headers=headers).status_code == 200

    with seeded_app.app.app_context():
        envelope = seeded_app.ESignatureEnvelope.query.one()
        document = seeded_app.SignatureDocument.query.one()
        assert envelope.status == "signed"
        assert envelope.completed_at and envelope.signed_filename
        assert envelope.signed_checksum_sha256 == hashlib.sha256(SIGNED_BYTES).hexdigest()
        assert document.status == "signed"
        assert document.buyer_signed_at and document.seller_signed_at
        assert seeded_app.ESignatureEvent.query.count() == 1
        assert not seeded_app.completion_blockers(document.introduction)

    login(client, "buyer")
    download = client.get("/completion/signature-documents/1/signed-download")
    assert download.status_code == 200
    assert download.data == SIGNED_BYTES


def test_webhook_payload_cannot_spoof_authoritative_status(client, seeded_app, monkeypatch):
    intro_id = make_introduction(seeded_app)
    fake = FakeSignable()
    configure_signable(seeded_app, fake, monkeypatch)
    login(client, "seller")
    upload_document(client, intro_id)
    client.post("/completion/signature-documents/1/signable/send", data={"confirm_tags": "on"})
    auth = base64.b64encode(b"ownerlane-hook:strong-test-secret").decode()
    response = client.post(
        "/webhooks/signable",
        data={
            "envelope_fingerprint": "env-ownerlane-1",
            "action": "signed-envelope-complete",
            "contact_email": "attacker@example.test",
        },
        headers={"Authorization": f"Basic {auth}"},
    )
    assert response.status_code == 200
    with seeded_app.app.app_context():
        assert seeded_app.ESignatureEnvelope.query.one().status == "sent"
        assert seeded_app.SignatureDocument.query.one().status == "ready"


def test_provider_errors_are_retriable_only_when_outcome_is_known(client, seeded_app, monkeypatch):
    class FailedSignable(FakeSignable):
        def send_document(self, **kwargs):
            raise SignableAPIError("Signable rejected the request.")

    intro_id = make_introduction(seeded_app)
    configure_signable(seeded_app, FailedSignable(), monkeypatch)
    login(client, "seller")
    upload_document(client, intro_id)
    response = client.post(
        "/completion/signature-documents/1/signable/send",
        data={"confirm_tags": "on"},
        follow_redirects=True,
    )
    assert b"Signable rejected the request" in response.data
    with seeded_app.app.app_context():
        envelope = seeded_app.ESignatureEnvelope.query.one()
        assert envelope.status == "failed" and envelope.request_attempts == 1

    configure_signable(seeded_app, FakeSignable(), monkeypatch)
    assert client.post(
        "/completion/signature-documents/1/signable/send",
        data={"confirm_tags": "on"},
    ).status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.ESignatureEnvelope.query.one().request_attempts == 2


def test_provider_document_disables_manual_signing_and_cancels_before_void(client, seeded_app, monkeypatch):
    intro_id = make_introduction(seeded_app)
    fake = FakeSignable()
    configure_signable(seeded_app, fake, monkeypatch)
    login(client, "seller")
    upload_document(client, intro_id)
    client.post("/completion/signature-documents/1/signable/send", data={"confirm_tags": "on"})
    assert client.post(
        "/completion/signature-documents/1/status", data={"action": "sign"}
    ).status_code == 400
    assert client.post(
        "/completion/signature-documents/1/status", data={"action": "void"}
    ).status_code == 302
    assert fake.cancelled == ["env-ownerlane-1"]
    with seeded_app.app.app_context():
        assert seeded_app.ESignatureEnvelope.query.one().status == "cancelled"
        document = seeded_app.SignatureDocument.query.one()
        assert document.status == "void" and document.is_required is False
