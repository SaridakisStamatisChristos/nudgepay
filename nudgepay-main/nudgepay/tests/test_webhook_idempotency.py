from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import delete, select

from app.db import init_db, session_scope
from app.main import app
from app.models import Client, Invoice, ProcessedWebhook, User


pytestmark = pytest.mark.integration


def _bootstrap_invoice() -> int:
    init_db()
    with session_scope() as session:
        session.exec(delete(ProcessedWebhook))
        session.exec(delete(Invoice))
        session.exec(delete(Client))
        session.exec(delete(User))
        session.commit()

        user = User(id=1, email="merchant@example.com", password_hash="test-hash")
        session.add(user)
        session.commit()

        client = Client(user_id=1, name="Acme", email="acme@example.com")
        session.add(client)
        session.commit()
        invoice = Invoice(
            user_id=1,
            client_id=client.id,
            number="INV-555",
            amount_cents=5000,
            due_date=date.today() + timedelta(days=3),
        )
        session.add(invoice)
        session.commit()
        return invoice.id


def test_webhook_idempotency(monkeypatch):
    invoice_id = _bootstrap_invoice()
    client = TestClient(app, base_url="https://testserver")

    fake_event = {
        "id": "evt_test_1",
        "type": "payment_intent.succeeded",
        "data": {"object": {"metadata": {"invoice_id": str(invoice_id)}}},
    }

    import app.main as mainmod

    mainmod._stripe_breaker.reset()
    monkeypatch.setattr(mainmod, "verify_webhook", lambda sig, body: fake_event)

    payload = b"{}"
    headers = {"stripe-signature": "sig"}
    first = client.post("/webhooks/stripe", data=payload, headers=headers)
    assert first.status_code == 200

    second = client.post("/webhooks/stripe", data=payload, headers=headers)
    assert second.status_code == 200

    with session_scope() as session:
        invoice = session.get(Invoice, invoice_id)
        assert invoice.status == "Paid"
        count = session.exec(select(ProcessedWebhook).where(ProcessedWebhook.event_id == "evt_test_1")).all()
        assert len(count) == 1
