from datetime import date, timedelta


from fastapi.testclient import TestClient
from sqlmodel import delete

from app.admins import ensure_admin
from app.db import init_db, session_scope
from app.main import app
from app.metrics import (
    configure_metrics,
    disable_metrics,
    record_login_attempt,
    record_login_throttle,
)
from app.models import AdminUser, Client, Invoice, ProcessedWebhook, ReminderLog, User


def _csrf_token(client: TestClient, path: str = "/invoices") -> str:
    response = client.get(path, follow_redirects=True)
    header_token = response.headers.get("X-CSRF-Token")
    if header_token:
        return header_token

    marker = 'name="_csrf_token" value="'
    html = response.text
    start = html.find(marker)
    assert start != -1, "CSRF token missing"
    start += len(marker)
    end = html.find('"', start)
    assert end != -1
    return html[start:end]


def test_metrics_endpoint_reports_service_counters(monkeypatch):
    client = TestClient(app, base_url="https://testserver")
    init_db()

    with session_scope() as session:
        session.exec(delete(ReminderLog))
        session.exec(delete(ProcessedWebhook))
        session.exec(delete(Invoice))
        session.exec(delete(AdminUser))
        session.exec(delete(Client))
        session.exec(delete(User))
        session.commit()

        user = User(id=1, email="merchant@example.com", password_hash="test-hash")
        session.add(user)
        session.commit()

        client_record = Client(user_id=1, name="Metrics Co", email="ops@example.com")
        session.add(client_record)
        session.commit()
        invoice = Invoice(
            user_id=1,
            client_id=client_record.id,
            number="INV-METRICS",
            amount_cents=5000,
            due_date=date.today() + timedelta(days=3),
        )
        session.add(invoice)
        session.commit()
        invoice_id = invoice.id

        ensure_admin(
            session,
            email="metrics@example.com",
            password="Password123!",
            role="superadmin",
        )

    monkeypatch.setattr("app.emailer.send_email", lambda *args, **kwargs: None)

    login_token = _csrf_token(client, "/login")
    login = client.post(
        "/login",
        data={
            "email": "metrics@example.com",
            "password": "Password123!",
            "_csrf_token": login_token,
        },
        headers={"X-CSRF-Token": login_token},
        follow_redirects=True,
    )
    assert login.status_code in (200, 303)

    response = client.get("/healthz")
    assert response.status_code == 200

    token = _csrf_token(client)
    trigger = client.post(
        f"/invoices/{invoice_id}/send-nudge",
        data={"version": 1, "_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert trigger.status_code == 200

    fake_event = {
        "id": "evt_test_123",
        "type": "payment_intent.succeeded",
        "data": {"object": {"metadata": {"invoice_id": str(invoice_id)}}},
    }
    monkeypatch.setattr("app.main.verify_webhook", lambda sig, body: fake_event)

    webhook = client.post(
        "/webhooks/stripe",
        data=b"{}",
        headers={"stripe-signature": "sig"},
    )
    assert webhook.status_code == 200

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    payload = metrics.text

    assert "nudgepay_http_requests_total" in payload
    assert 'route="/healthz"' in payload
    assert 'nudgepay_reminders_total{stage="manual",status="sent"}' in payload
    assert 'nudgepay_payments_total{source="stripe_webhook"}' in payload


def test_login_metrics_render_without_prometheus():
    recorder = configure_metrics("test")
    try:
        record_login_attempt("success", factor="password")
        record_login_attempt("invalid_credentials", factor="password")
        record_login_throttle("blocked", retry_after=30)
        record_login_throttle("reset")
        payload = recorder.render()
    finally:
        disable_metrics()

    assert "test_login_attempts_total" in payload
    assert 'test_login_attempts_total{factor="password",result="success"}' in payload
    assert 'test_login_attempts_total{factor="password",result="invalid_credentials"}' in payload
    assert 'test_login_throttle_events_total{event="blocked"}' in payload
    assert 'test_login_throttle_events_total{event="reset"}' in payload
    assert "test_login_throttle_retry_seconds_bucket" in payload
