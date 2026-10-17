from datetime import date

import pytest
from fastapi.testclient import TestClient
from sqlmodel import delete, select

from app.admins import assign_role, ensure_admin
from app.db import init_db, session_scope
from app.main import app
from app.models import AdminUser, Client, Invoice, User


def _csrf_token(client: TestClient, path: str) -> str:
    response = client.get(path, follow_redirects=True)
    header_token = response.headers.get("X-CSRF-Token")
    if header_token:
        return header_token

    marker = 'name="_csrf_token" value="'
    html = response.text
    start = html.find(marker)
    assert start != -1, f"CSRF token not found in {path}"
    start += len(marker)
    end = html.find('"', start)
    assert end != -1
    return html[start:end]


@pytest.fixture
def authed_client(monkeypatch):
    init_db()
    with session_scope() as session:
        session.exec(delete(AdminUser))
        session.exec(delete(Invoice))
        session.exec(delete(Client))
        session.exec(delete(User))
        session.commit()

        admin = ensure_admin(
            session,
            email="viewer@example.com",
            password="Secret123!",
            role="viewer",
        )
        admin_id = admin.id

        user = User(id=1, email="merchant@example.com", password_hash="test-hash")
        session.add(user)
        session.commit()

        client_record = Client(user_id=1, name="Acme", email="acme@example.com")
        session.add(client_record)
        session.commit()

        invoice = Invoice(
            user_id=1,
            client_id=client_record.id,
            number="INV-100",
            amount_cents=1000,
            due_date=date.today(),
        )
        session.add(invoice)
        session.commit()
        invoice_id = invoice.id
        client_id = client_record.id

    import app.main as mainmod

    monkeypatch.setattr(mainmod, "ensure_payment_link", lambda *args, **kwargs: "https://example.com/pay")
    monkeypatch.setattr(mainmod, "queue_reminder", lambda *args, **kwargs: None)

    client = TestClient(app, base_url="https://testserver")
    login_token = _csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "email": "viewer@example.com",
            "password": "Secret123!",
            "_csrf_token": login_token,
        },
        headers={"X-CSRF-Token": login_token},
        follow_redirects=True,
    )
    assert response.status_code in (200, 303)
    try:
        yield client, invoice_id, client_id, admin_id
    finally:
        client.close()


def test_permission_enforcement_refreshes_session(authed_client):
    client, invoice_id, client_id, admin_id = authed_client

    # viewer can read clients but cannot toggle reminders or settings
    resp = client.get("/clients", follow_redirects=True)
    assert resp.status_code == 200

    token = _csrf_token(client, "/invoices")
    resp = client.post(
        f"/invoices/{invoice_id}/send-nudge",
        data={"version": 1, "_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert resp.status_code == 403

    resp = client.get("/settings")
    assert resp.status_code == 403

    # escalate to operator and ensure queue actions become available without new login
    with session_scope() as session:
        assign_role(session, admin_id=admin_id, role="operator")
        invoice = session.get(Invoice, invoice_id)
        current_version = invoice.version

    token = _csrf_token(client, "/invoices")
    resp = client.post(
        f"/invoices/{invoice_id}/send-nudge",
        data={"version": current_version, "_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert resp.status_code == 200

    # operators still cannot manage settings
    resp = client.get("/settings")
    assert resp.status_code == 403

    # promote to superadmin for full control
    with session_scope() as session:
        assign_role(session, admin_id=admin_id, role="superadmin")

    resp = client.get("/settings")
    assert resp.status_code == 200

    # ensure permissions stored in session were refreshed
    with session_scope() as session:
        stored = session.exec(select(AdminUser).where(AdminUser.id == admin_id)).first()
        assert stored.role == "superadmin"


def test_session_refresh_endpoint_returns_permissions(authed_client):
    client, _invoice_id, _client_id, admin_id = authed_client

    token = _csrf_token(client, "/invoices")
    initial = client.post(
        "/session/refresh",
        data={"_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert initial.status_code == 200
    initial_payload = initial.json()
    assert initial_payload["role"] == "viewer"
    assert "invoice:read" in initial_payload["permissions"]

    with session_scope() as session:
        assign_role(session, admin_id=admin_id, role="superadmin")

    token = _csrf_token(client, "/invoices")
    refreshed = client.post(
        "/session/refresh",
        data={"_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert refreshed.status_code == 200
    payload = refreshed.json()
    assert payload["role"] == "superadmin"
    assert "queue:manage" in payload["permissions"]
