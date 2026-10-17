import hashlib
import hmac
import time
import pytest
from dataclasses import replace

from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.db import init_db
from app.main import app, _validate_cron_request
from app.config import get_settings


def test_health_check_returns_ok():
    client = TestClient(app, base_url="https://testserver")
    init_db()
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.text == "ok"


def test_security_headers_and_request_id_are_included():
    client = TestClient(app, base_url="https://testserver")
    init_db()
    response = client.get("/healthz", headers={"X-Request-ID": "abc123"})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == "abc123"
    assert response.headers.get("Content-Security-Policy", "").startswith("default-src")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"


def test_automation_endpoint_requires_mutual_tls(monkeypatch):
    init_db()
    original = get_settings()
    patched = replace(
        original,
        cron_mutual_tls_required=True,
        cron_mutual_tls_fingerprints=("allowed",),
    )
    monkeypatch.setattr("app.main.settings", patched)

    body = b"{}"
    timestamp = str(int(time.time()))
    digest = hashlib.sha256(body).hexdigest()
    payload = f"{timestamp}.{digest}".encode("utf-8")
    signature = hmac.new(patched.cron_hmac_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    def make_request(fingerprint: str) -> Request:
        headers = [
            (b"x-cron-timestamp", timestamp.encode("utf-8")),
            (b"x-cron-signature", signature.encode("utf-8")),
            (b"x-client-cert-thumbprint", fingerprint.encode("utf-8")),
        ]

        async def receive() -> dict[str, object]:
            return {"type": "http.request", "body": body, "more_body": False}

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/internal/automation/dlq",
            "headers": headers,
        }
        return Request(scope, receive)

    with pytest.raises(HTTPException) as exc:
        _validate_cron_request(make_request("wrong"), body=body)
    assert exc.value.status_code == 403

    _validate_cron_request(make_request("allowed"), body=body)
