"""Scoped service token helpers for high-risk automation."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Iterable, Sequence

from sqlmodel import Session, select

from .config import get_settings
from .db import engine
from .models import ServiceToken


def _ensure_session(session: Session | None) -> tuple[Session, Session | None]:
    if session is not None:
        return session, None
    managed = Session(engine)
    return managed, managed


def _hash_token(raw: str) -> str:
    settings = get_settings()
    pepper = getattr(settings, "service_token_pepper", "nudgepay-pepper")
    return hashlib.sha256(f"{pepper}:{raw}".encode("utf-8")).hexdigest()


def create_service_token(
    *,
    name: str,
    scopes: Iterable[str],
    created_by: str,
    description: str | None = None,
    ttl_minutes: int | None = None,
    session: Session | None = None,
) -> tuple[str, ServiceToken]:
    """Create a new service token and return the plain-text secret."""

    managed_session, owned_session = _ensure_session(session)
    try:
        token_value = secrets.token_urlsafe(32)
        hashed = _hash_token(token_value)
        expires_at = None
        if ttl_minutes:
            expires_at = datetime.now(tz=UTC) + timedelta(minutes=ttl_minutes)
        record = ServiceToken(
            name=name,
            token_prefix=token_value[:12],
            token_hash=hashed,
            scopes=sorted({scope.strip() for scope in scopes if scope.strip()}),
            created_by=created_by,
            expires_at=expires_at,
            description=description,
        )
        managed_session.add(record)
        managed_session.flush()
        managed_session.refresh(record)
        return token_value, record
    finally:
        if owned_session is not None:
            owned_session.commit()
            owned_session.close()


def revoke_service_token(
    *,
    token_id: int,
    session: Session | None = None,
) -> ServiceToken:
    """Revoke an existing service token."""

    managed_session, owned_session = _ensure_session(session)
    try:
        record = managed_session.get(ServiceToken, token_id)
        if record is None:
            raise LookupError(f"Service token {token_id} not found")
        record.revoked = True
        record.revoked_at = datetime.now(tz=UTC)
        record.last_used_at = datetime.now(tz=UTC)
        managed_session.add(record)
        managed_session.flush()
        managed_session.refresh(record)
        return record
    finally:
        if owned_session is not None:
            owned_session.commit()
            owned_session.close()


def validate_service_token(
    token: str,
    *,
    scope: str,
    session: Session,
) -> ServiceToken:
    """Validate the supplied service token against ``scope``."""

    hashed = _hash_token(token)
    record = session.exec(select(ServiceToken).where(ServiceToken.token_hash == hashed)).first()
    if record is None or record.revoked:
        raise PermissionError("Service token is invalid or revoked")
    if record.expires_at and record.expires_at < datetime.now(tz=UTC):
        raise PermissionError("Service token has expired")

    allowed = set(record.scopes or [])
    if "*" not in allowed and scope not in allowed:
        raise PermissionError("Service token scope does not permit this action")

    record.last_used_at = datetime.now(tz=UTC)
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def list_active_tokens(session: Session) -> Sequence[ServiceToken]:
    return session.exec(select(ServiceToken).where(ServiceToken.revoked.is_(False))).all()


__all__ = [
    "create_service_token",
    "revoke_service_token",
    "validate_service_token",
    "list_active_tokens",
]
