"""Small, provider-specific client for Signable's e-signature API."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from urllib.parse import urlparse

import requests


class SignableAPIError(RuntimeError):
    def __init__(self, message: str, *, ambiguous: bool = False):
        super().__init__(message)
        self.ambiguous = ambiguous


@dataclass(frozen=True)
class DownloadedFile:
    content: bytes
    mime_type: str
    extension: str


class SignableClient:
    def __init__(self, api_key: str, base_url: str = "https://api.signable.co.uk/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, **kwargs):
        try:
            response = requests.request(
                method,
                f"{self.base_url}/{path.lstrip('/')}",
                auth=(self.api_key, "x"),
                timeout=(5, 30),
                allow_redirects=False,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise SignableAPIError(
                "Signable did not return a response; the outcome is unknown.",
                ambiguous=True,
            ) from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise SignableAPIError(
                f"Signable returned HTTP {response.status_code}."
            )
        try:
            return response.json()
        except ValueError as exc:
            raise SignableAPIError("Signable returned an invalid response.") from exc

    def send_document(
        self,
        *,
        title: str,
        filename: str,
        content: bytes,
        signers: list[dict],
        metadata: dict,
        redirect_url: str | None = None,
    ) -> dict:
        payload = {
            "envelope_title": title,
            "envelope_all_at_once_enabled": True,
            "envelope_parties": signers,
            "envelope_documents": [
                {
                    "document_title": title,
                    "document_file_name": filename,
                    "document_file_content": base64.b64encode(content).decode("ascii"),
                }
            ],
            "envelope_meta": metadata,
        }
        if redirect_url:
            payload["envelope_redirect_url"] = redirect_url
        return self._request("POST", "/envelopes", json=payload)

    def get_envelope(self, fingerprint: str) -> dict:
        return self._request("GET", f"/envelopes/{fingerprint}")

    def cancel_envelope(self, fingerprint: str) -> dict:
        return self._request("PUT", f"/envelopes/{fingerprint}/cancel")

    @staticmethod
    def signed_download_url(envelope_data: dict) -> str | None:
        url = envelope_data.get("envelope_signed_pdf")
        if url:
            return url
        for document in envelope_data.get("envelope_documents") or []:
            url = document.get("document_signed_pdf")
            if url:
                return url
        return None

    @staticmethod
    def download_signed_file(url: str, *, max_bytes: int = 25 * 1024 * 1024) -> DownloadedFile:
        parsed = urlparse(url)
        allowed_hosts = {
            "api.signableapi.com",
            "api.signable.co.uk",
            "docs.signable.co.uk",
        }
        if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
            raise SignableAPIError("Signable returned an unsafe document URL.")
        try:
            response = requests.get(
                url,
                timeout=(5, 30),
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            raise SignableAPIError("The signed document could not be downloaded.") from exc
        if response.status_code != 200:
            raise SignableAPIError(
                f"The signed document returned HTTP {response.status_code}."
            )
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > max_bytes:
                    raise SignableAPIError("The signed document exceeds the storage limit.")
            except ValueError as exc:
                raise SignableAPIError("Signable returned an invalid document size.") from exc
        chunks = []
        size = 0
        for chunk in response.iter_content(1024 * 1024):
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                raise SignableAPIError("The signed document exceeds the storage limit.")
            chunks.append(chunk)
        mime_type = (response.headers.get("Content-Type") or "application/pdf").split(";", 1)[0]
        if mime_type not in {"application/pdf", "application/zip", "application/octet-stream"}:
            raise SignableAPIError("Signable returned an unexpected document type.")
        extension = ".zip" if mime_type == "application/zip" else ".pdf"
        return DownloadedFile(b"".join(chunks), mime_type, extension)
