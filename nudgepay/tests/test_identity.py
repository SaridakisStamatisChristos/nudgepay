import pytest

from app import identity
from app.db import init_db, session_scope
from app.models import AdminUser
from sqlmodel import select


@pytest.fixture(autouse=True)
def reset_identity_state(monkeypatch):
    monkeypatch.setattr(identity, "_PROVIDERS", {})
    yield


def test_federated_login_creates_admin(monkeypatch):
    init_db()
    provider = identity.FederationProvider(
        slug="okta",
        issuer="https://example.okta.com",
        audience="nudgepay",
        role_mapping={"admin": "superadmin"},
    )
    identity.register_provider(provider)

    with session_scope() as session:
        result = identity.federated_login(
            "okta",
            {
                "iss": "https://example.okta.com",
                "aud": "nudgepay",
                "sub": "user-123",
                "email": "federated@example.com",
                "role": "admin",
            },
            session=session,
        )

        assert result.created
        assert result.provider == "okta"
        admin = session.get(AdminUser, result.admin.id)
        assert admin.external_id == "user-123"
        assert admin.role == "superadmin"


def test_apply_scim_event_updates_admin():
    init_db()
    with session_scope() as session:
        admin = AdminUser(
            email="scim@example.com",
            password_hash="hash",
            permissions=["invoice:read"],
        )
        session.add(admin)
        session.commit()

    with session_scope() as session:
        event = identity.SCIMEvent(
            identifier="scim-user-1",
            email="scim@example.com",
            role="operator",
            permissions=("invoice:write",),
        )
        updated = identity.apply_scim_event(event, session=session)
        assert updated.is_active
        assert updated.role == "operator"
        assert "invoice:write" in updated.permissions


def test_hardware_enrollment_and_verification():
    init_db()
    with session_scope() as session:
        admin = AdminUser(
            email="hardware@example.com",
            password_hash="hash",
        )
        session.add(admin)
        session.commit()

    with session_scope() as session:
        admin = session.exec(select(AdminUser).where(AdminUser.email == "hardware@example.com")).first()
        assert admin is not None
        enrolled = identity.enroll_hardware_key(admin, "ABC123", session=session)
        assert "abc123" in enrolled.hardware_key_fingerprints

    with session_scope() as session:
        admin = session.exec(select(AdminUser).where(AdminUser.email == "hardware@example.com")).first()
        assert not identity.verify_hardware_assertion(admin, None)
        assert identity.verify_hardware_assertion(admin, "abc123")
