from datetime import date, timedelta


import pytest
from fastapi.testclient import TestClient
from sqlmodel import delete, select

from app.admins import ensure_admin
from app.db import init_db, session_scope
from app.main import app
from app.models import AdminUser, Client, Invoice, ReminderLog, User


pytestmark = pytest.mark.integration


def _csrf_token(client: TestClient, path: str = "/invoices") -> str:
    response = client.get(path, follow_redirects=True)
    header_token = response.headers.get("X-CSRF-Token")
    if header_token:
        return header_token

    marker = 'name="_csrf_token" value="'
    html = response.text
    start = html.find(marker)
    assert start != -1, "CSRF token not found"
    start += len(marker)
    end = html.find('"', start)
    assert end != -1
    return html[start:end]

def test_toggle_and_nudge(monkeypatch):
    client = TestClient(app, base_url="https://testserver")

    init_db()
    with session_scope() as session:
        session.exec(delete(ReminderLog))
        session.exec(delete(Invoice))
        session.exec(delete(AdminUser))
        session.exec(delete(Client))
        session.exec(delete(User))
        session.commit()

        user = User(id=1, email="merchant@example.com", password_hash="test-hash")
        session.add(user)
        session.commit()

        client_record = Client(user_id=1, name="ACME", email="acme@example.com")
        session.add(client_record)
        session.commit()
        invoice = Invoice(
            user_id=1,
            client_id=client_record.id,
            number="INV-1",
            amount_cents=1000,
            due_date=date.today() + timedelta(days=3),
        )
        session.add(invoice)
        session.commit()
        inv_id = invoice.id

        ensure_admin(
            session,
            email="ops@example.com",
            password="Password123!",
            role="superadmin",
        )

    calls: dict[str, str] = {}

    def fake_send_email(to, subject, html):
        calls["to"] = to
        calls["subject"] = subject
        calls["html"] = html
    import app.emailer as emailer
    monkeypatch.setattr(emailer, "send_email", fake_send_email)

    login_token = _csrf_token(client, "/login")
    login = client.post(
        "/login",
        data={
            "email": "ops@example.com",
            "password": "Password123!",
            "_csrf_token": login_token,
        },
        headers={"X-CSRF-Token": login_token},
        follow_redirects=True,
    )
    assert login.status_code in (200, 303)

    token = _csrf_token(client)
    r = client.post(
        f"/invoices/{inv_id}/toggle-reminders",
        data={"version": 1, "_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200

    with session_scope() as session:
        refreshed = session.get(Invoice, inv_id)
        assert refreshed is not None
        current_version = refreshed.version

    token = _csrf_token(client)
    r = client.post(
        f"/invoices/{inv_id}/send-nudge",
        data={"version": current_version, "_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200
    assert calls.get("to") == "acme@example.com"

    with session_scope() as session:
        logs = session.exec(select(ReminderLog)).all()
        assert any(log.kind == "manual" for log in logs)
