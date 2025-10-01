from datetime import date, timedelta


import pytest
from fastapi.testclient import TestClient
from sqlmodel import delete

from app.db import init_db, session_scope
from app.main import app
from app.models import Client, Invoice, User


pytestmark = pytest.mark.integration

def test_webhook_marks_paid(monkeypatch):
    client = TestClient(app, base_url="https://testserver")
    init_db()
    with session_scope() as session:
        session.exec(delete(Invoice))
        session.exec(delete(Client))
        session.exec(delete(User))
        session.commit()

        user = User(id=1, email="merchant@example.com", password_hash="test-hash")
        session.add(user)
        session.commit()

        client_record = Client(user_id=1, name="X Corp", email="x@example.com")
        session.add(client_record)
        session.commit()
        invoice = Invoice(
            user_id=1,
            client_id=client_record.id,
            number="INV-999",
            amount_cents=12345,
            due_date=date.today() + timedelta(days=1),
        )
        session.add(invoice)
        session.commit()
        inv_id = invoice.id

    fake_event = {
        "type": "payment_intent.succeeded",
        "data": {"object": {"metadata": {"invoice_id": str(inv_id)}}}
    }
    import app.main as mainmod
    mainmod._stripe_breaker.reset()
    monkeypatch.setattr(mainmod, "verify_webhook", lambda sig, body: fake_event)

    r = client.post("/webhooks/stripe", data=b"{}", headers={"stripe-signature": "deadbeef"})
    assert r.status_code == 200

    with session_scope() as session:
        stored_invoice = session.get(Invoice, inv_id)
        assert stored_invoice.status == "Paid"
        assert stored_invoice.updated_at is not None


def test_webhook_disallows_unlisted_events(monkeypatch):
    client = TestClient(app, base_url="https://testserver")
    init_db()

    fake_event = {"type": "customer.created", "data": {"object": {}}}
    import app.main as mainmod

    mainmod._stripe_breaker.reset()
    monkeypatch.setattr(mainmod, "verify_webhook", lambda sig, body: fake_event)

    response = client.post("/webhooks/stripe", data=b"{}", headers={"stripe-signature": "sig"})
    assert response.status_code == 202
    payload = response.json()
    assert payload["ignored"] is True
