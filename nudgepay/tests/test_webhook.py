import hashlib
import hmac
import time
from dataclasses import replace

from app.main import app
from fastapi.testclient import TestClient

def test_internal_requires_secret():
    client = TestClient(app, base_url="https://testserver")
    resp = client.post("/internal/run-reminders")
    assert resp.status_code == 401


def _signed_headers(settings, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    digest = hashlib.sha256(body).hexdigest()
    signature = hmac.new(
        settings.cron_hmac_secret.encode("utf-8"),
        f"{timestamp}.{digest}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {"X-Cron-Timestamp": timestamp, "X-Cron-Signature": signature}


def test_internal_cron_requires_mutual_tls(monkeypatch):
    from app import main as mainmod

    client = TestClient(app, base_url="https://testserver")
    body = b""
    patched_settings = replace(
        mainmod.settings,
        cron_mutual_tls_required=True,
        cron_mutual_tls_fingerprints=("aa:bb",),
    )
    monkeypatch.setattr(mainmod, "settings", patched_settings, raising=False)
    monkeypatch.setattr(mainmod.app.state, "settings", patched_settings, raising=False)
    headers = _signed_headers(patched_settings, body)

    monkeypatch.setattr(mainmod, "run_daily_reminders", lambda base_url: None)

    response = client.post("/internal/run-reminders", data=body, headers=headers)
    assert response.status_code == 401

    headers["X-Client-Cert-Thumbprint"] = "aa:bb"
    response_ok = client.post("/internal/run-reminders", data=body, headers=headers)
    assert response_ok.status_code == 200
