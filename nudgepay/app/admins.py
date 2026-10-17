"""Helpers for managing administrative users."""

from __future__ import annotations

import secrets
from typing import Iterable, Optional, Sequence, Tuple

import bcrypt
from sqlmodel import Session, select

from .models import AdminUser


class AdminAlreadyExistsError(RuntimeError):
    """Raised when attempting to create an admin with a duplicate email."""


def _normalize_email(email: str) -> str:
    return email.strip().lower()


_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"invoice:read", "metrics:view", "webhook:read"}),
    "operator": frozenset(
        {
            "invoice:read",
            "invoice:write",
            "metrics:view",
            "queue:manage",
            "webhook:read",
            "webhook:retry",
        }
    ),
    "superadmin": frozenset(
        {
            "invoice:read",
            "invoice:write",
            "metrics:view",
            "queue:manage",
            "webhook:read",
            "webhook:retry",
            "admin:manage",
            "security:rotate-secrets",
            "settings:manage",
        }
    ),
}

_WILDCARD_PERMISSION = "*"
_VALID_PERMISSIONS = {_WILDCARD_PERMISSION}.union(*_ROLE_PERMISSIONS.values())


def _normalize_role(role: str) -> str:
    normalized = role.strip().lower()
    if normalized not in _ROLE_PERMISSIONS:
        raise ValueError(f"Unknown admin role '{role}'")
    return normalized


def _resolve_permissions(role: str, extras: Iterable[str] | None) -> list[str]:
    base = set(_ROLE_PERMISSIONS[_normalize_role(role)])
    if extras:
        invalid = [perm for perm in extras if perm not in _VALID_PERMISSIONS]
        if invalid:
            raise ValueError(f"Unsupported permissions requested: {', '.join(sorted(invalid))}")
        base.update(extras)
    return sorted(base)


def list_admins(session: Session) -> list[AdminUser]:
    return session.exec(select(AdminUser).order_by(AdminUser.email)).all()


def ensure_admin(
    session: Session,
    *,
    email: str,
    password: str,
    totp_secret: Optional[str] = None,
    role: str = "viewer",
    permissions: Iterable[str] | None = None,
) -> AdminUser:
    """Create a new administrative user if it does not already exist."""

    normalized = _normalize_email(email)
    existing = session.exec(select(AdminUser).where(AdminUser.email == normalized)).first()
    if existing:
        raise AdminAlreadyExistsError(f"Admin '{normalized}' already exists")

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    computed_permissions = _resolve_permissions(role, permissions)
    admin = AdminUser(
        email=normalized,
        password_hash=password_hash,
        totp_secret=totp_secret,
        role=_normalize_role(role),
        permissions=computed_permissions,
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def rotate_password(session: Session, *, admin_id: int, new_password: str) -> AdminUser:
    admin = session.get(AdminUser, admin_id)
    if not admin:
        raise LookupError(f"Admin with id {admin_id} not found")

    admin.password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def deactivate_admin(session: Session, *, admin_id: int) -> AdminUser:
    admin = session.get(AdminUser, admin_id)
    if not admin:
        raise LookupError(f"Admin with id {admin_id} not found")

    admin.is_active = False
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def assign_role(
    session: Session,
    *,
    admin_id: int,
    role: str,
    extra_permissions: Iterable[str] | None = None,
) -> AdminUser:
    admin = session.get(AdminUser, admin_id)
    if not admin:
        raise LookupError(f"Admin with id {admin_id} not found")

    admin.role = _normalize_role(role)
    admin.permissions = _resolve_permissions(admin.role, extra_permissions)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def generate_totp_secret() -> str:
    """Return a random base32-compatible TOTP secret."""

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(32))


def bulk_sync_admins(
    session: Session,
    *,
    admins: Iterable[
        Tuple[str, str]
        | Tuple[str, str, str]
        | Tuple[str, str, str, Sequence[str]]
    ],
) -> None:
    """Replace the current admin roster with ``admins``.

    ``admins`` should be an iterable of ``(email, password_hash)`` pairs.
    """

    existing = {admin.email: admin for admin in list_admins(session)}
    seen: set[str] = set()
    for entry in admins:
        extra_permissions: Sequence[str] | None = None
        if len(entry) == 2:
            email, password_hash = entry  # type: ignore[misc]
            normalized = _normalize_email(email)
            record = existing.get(normalized)
            role = record.role if record else "viewer"
        elif len(entry) == 3:
            email, password_hash, role = entry  # type: ignore[misc]
            normalized = _normalize_email(email)
            record = existing.get(normalized)
        elif len(entry) == 4:
            email, password_hash, role, extra_permissions = entry  # type: ignore[misc]
            normalized = _normalize_email(email)
            record = existing.get(normalized)
        else:  # pragma: no cover - defensive
            raise ValueError("Unsupported admin tuple shape")

        resolved_role = _normalize_role(role)
        resolved_permissions = _resolve_permissions(resolved_role, extra_permissions)
        seen.add(normalized)
        if record is None:
            record = AdminUser(
                email=normalized,
                password_hash=password_hash,
                role=resolved_role,
                permissions=resolved_permissions,
            )
        else:
            record.password_hash = password_hash
            record.is_active = True
            record.role = resolved_role
            record.permissions = resolved_permissions
        session.add(record)

    for email, admin in existing.items():
        if email not in seen:
            admin.is_active = False
            session.add(admin)

    session.commit()


__all__ = [
    "AdminAlreadyExistsError",
    "assign_role",
    "bulk_sync_admins",
    "deactivate_admin",
    "ensure_admin",
    "generate_totp_secret",
    "list_admins",
    "rotate_password",
]
