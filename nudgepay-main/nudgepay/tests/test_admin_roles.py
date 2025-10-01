from sqlmodel import delete

from app.admins import assign_role, bulk_sync_admins, ensure_admin, list_admins
from app.db import init_db, session_scope
from app.models import AdminUser


def _reset_admins() -> None:
    init_db()
    with session_scope() as session:
        session.exec(delete(AdminUser))
        session.commit()


def test_ensure_admin_assigns_role_and_permissions():
    _reset_admins()
    with session_scope() as session:
        admin = ensure_admin(
            session,
            email="ops@example.com",
            password="secret123",
            role="operator",
            permissions=["webhook:retry"],
        )
        assert admin.role == "operator"
        assert "queue:manage" in admin.permissions
        assert "webhook:retry" in admin.permissions

        updated = assign_role(session, admin_id=admin.id, role="superadmin", extra_permissions=["*"])
        assert updated.role == "superadmin"
        assert "security:rotate-secrets" in updated.permissions
        assert "*" in updated.permissions


def test_bulk_sync_admins_supports_role_payloads():
    _reset_admins()
    with session_scope() as session:
        bulk_sync_admins(
            session,
            admins=[
                ("viewer@example.com", "hash1"),
                ("operator@example.com", "hash2", "operator"),
                ("super@example.com", "hash3", "superadmin", ["*"]),
            ],
        )

        admins = {admin.email: admin for admin in list_admins(session)}
        assert admins["viewer@example.com"].role == "viewer"
        assert "invoice:read" in admins["viewer@example.com"].permissions
        assert "queue:manage" in admins["operator@example.com"].permissions
        assert "*" in admins["super@example.com"].permissions
