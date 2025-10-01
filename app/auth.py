"""Authentication helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable, Optional

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select

from . import identity
from .audit import record_admin_event
from .config import Settings, get_settings, normalize_base32_secret
from .db import get_session
from .models import AdminUser
from .security import LoginThrottle

logger = logging.getLogger(__name__)
settings = get_settings()


def _build_throttle(config: Settings) -> LoginThrottle:
    return LoginThrottle(
        limit=config.login_rate_limit_attempts,
        window_seconds=config.login_rate_limit_window_seconds,
        block_seconds=config.login_rate_limit_block_seconds,
    )


_login_throttle = _build_throttle(settings)


@dataclass(slots=True)
class LoginResult:
    """Represents the outcome of a login attempt."""

    success: bool
    error: Optional[str] = None
    retry_after: Optional[int] = None


@dataclass(slots=True)
class SessionIdentity:
    """Snapshot of the current administrative session."""

    email: str | None
    role: str | None
    permissions: tuple[str, ...]
    authenticated: bool


def configure_security(config: Settings) -> None:
    """Refresh cached security settings (used by tests)."""

    global settings, _login_throttle
    settings = config
    _login_throttle = _build_throttle(config)


def verify_password_hash(password_hash: str, plain: str) -> bool:
    """Return ``True`` when the supplied plain-text password matches the hash."""

    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:  # pragma: no cover - bcrypt may raise different errors
        logger.warning("Failed to verify password hash", exc_info=True)
        return False


def _generate_totp(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = digest[offset : offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF
    return f"{code_int % 1_000_000:06d}"


def _verify_totp(code: str | None, *, override_secret: str | None = None) -> bool:
    """Validate the supplied TOTP code when configured."""

    secret_source = override_secret or settings.admin_totp_secret
    if not secret_source:
        return True
    if not code:
        return False
    candidate = code.strip()
    if len(candidate) != 6 or not candidate.isdigit():
        return False
    try:
        normalized_secret = normalize_base32_secret(secret_source)
    except ValueError:
        logger.error("Configured TOTP secret has an invalid base32 length")
        return False
    if not normalized_secret:
        logger.error("Configured TOTP secret is empty after normalization")
        return False
    try:
        secret = base64.b32decode(normalized_secret, casefold=True)
    except (binascii.Error, ValueError, TypeError):
        logger.error("Configured TOTP secret is invalid base32")
        return False

    timestamp = int(time.time() / 30)
    for drift in (-1, 0, 1):
        expected = _generate_totp(secret, timestamp + drift)
        if hmac.compare_digest(expected, candidate):
            return True
    return False


def require_login(request: Request) -> bool:
    """Ensure the user is authenticated before continuing."""

    if not request.session.get("authed"):
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return True


def _normalized_session_email(request: Request) -> str | None:
    email = request.session.get("admin_email")
    if not email:
        return None
    try:
        return str(email).strip().lower()
    except Exception:  # pragma: no cover - defensive guard for unexpected types
        return None


def _session_permissions(request: Request) -> set[str]:
    """Return the cached permissions associated with the active session."""

    raw_permissions = request.session.get("permissions", [])
    if isinstance(raw_permissions, list):
        return set(str(item) for item in raw_permissions)
    return set()


def session_identity(
    request: Request, *, permissions: Iterable[str] | None = None
) -> SessionIdentity:
    """Return a normalized view of the current session."""

    email = _normalized_session_email(request)
    role = request.session.get("role")
    normalized_role = str(role).strip().lower() if isinstance(role, str) else None
    if permissions is None:
        effective_permissions = _session_permissions(request)
    else:
        effective_permissions = {str(item) for item in permissions}
    ordered_permissions = tuple(sorted(effective_permissions))
    return SessionIdentity(
        email=email,
        role=normalized_role,
        permissions=ordered_permissions,
        authenticated=bool(request.session.get("authed")),
    )


def _refresh_permissions(request: Request, session: Session | None = None) -> set[str]:
    """Reload permissions from the data store when they are missing or stale."""

    if session is None:
        return _session_permissions(request)

    email = _normalized_session_email(request)
    if not email:
        return set()

    admin_record = session.exec(
        select(AdminUser).where(AdminUser.email == email, AdminUser.is_active.is_(True))
    ).first()

    if not admin_record:
        # The bootstrap superadmin does not have a database record.  Preserve the
        # session if it matches the configured credentials, otherwise clear the
        # session to force a new login.
        if email == settings.admin_email.strip().lower():
            request.session["permissions"] = ["*"]
            request.session["role"] = "superadmin"
            request.session["authed"] = True
            request.session.setdefault("admin_email", email)
            return {"*"}

        request.session.clear()
        return set()

    permissions = set(admin_record.permissions or [])
    request.session["permissions"] = sorted(permissions)
    request.session["role"] = admin_record.role
    # Sessions created before the middleware ordering change can lose the
    # ``authed`` sentinel while keeping the admin email.  Re-stamping it when we
    # successfully reload permissions keeps follow-up requests from appearing
    # unauthenticated.
    request.session["authed"] = True
    request.session.setdefault("admin_email", admin_record.email)
    return permissions


def refresh_session_permissions(request: Request, *, session: Session) -> set[str]:
    """Force-refresh the permission cache stored in the session."""

    return _refresh_permissions(request, session=session)


def has_permission(
    request: Request,
    permission: str,
    *,
    session: Session | None = None,
) -> bool:
    """Return ``True`` when the current user holds ``permission``."""

    target = "*" if permission == "*" else permission

    cached = _session_permissions(request)
    if session is None:
        return "*" in cached or target in cached

    refreshed = _refresh_permissions(request, session=session)
    if refreshed:
        cached = refreshed

    return "*" in cached or target in cached


def require_permission(permission: str):
    """Return a FastAPI dependency enforcing the specified permission."""

    def _dependency(
        request: Request,
        session: Session = Depends(get_session),
    ) -> bool:
        require_login(request)
        if has_permission(request, permission, session=session):
            return True
        actor = _normalized_session_email(request) or "unknown"
        ip_address = request.client.host if request.client else None
        record_admin_event(
            "auth.permission_denied",
            actor=actor,
            ip_address=ip_address,
            metadata={"permission": permission},
            session=session,
        )
        if session is not None:
            session.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    return _dependency


def _record_login_failure(
    request: Request,
    normalized_email: str,
    reason: str,
    *,
    session: Session | None,
) -> None:
    """Persist an audit event capturing the failed login attempt."""

    record_admin_event(
        "auth.login_failed",
        actor=normalized_email or "unknown",
        ip_address=_client_ip(request),
        metadata={"reason": reason},
        session=session,
    )
    if session is not None:
        session.commit()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _throttle_key(request: Request, email: str) -> str:
    return f"{email.strip().lower()}::{_client_ip(request)}"


def login(
    request: Request,
    email: str,
    password: str,
    *,
    totp_code: str | None = None,
    hardware_assertion: str | None = None,
    session: Session | None = None,
) -> LoginResult:
    """Attempt to authenticate the admin user."""

    normalized_email = email.strip().lower()
    key = _throttle_key(request, normalized_email)

    record_admin_event(
        "auth.login_attempt",
        actor=normalized_email or "unknown",
        ip_address=_client_ip(request),
        metadata={},
        session=session,
    )
    if session is not None:
        session.commit()

    if _login_throttle.is_blocked(key):
        retry_after = _login_throttle.retry_after(key)
        logger.warning("Login blocked for %s from %s", normalized_email, _client_ip(request))
        record_admin_event(
            "auth.login_rate_limited",
            actor=normalized_email or "unknown",
            ip_address=_client_ip(request),
            metadata={"retry_after": int(retry_after or 0)},
            session=session,
        )
        record_admin_event(
            "login",
            actor=normalized_email or "unknown",
            ip_address=_client_ip(request),
            metadata={"result": "rate_limited"},
            session=session,
        )
        if session is not None:
            session.commit()
        return LoginResult(False, "Too many attempts. Try again later.", retry_after=retry_after)

    admin_record: AdminUser | None = None
    if session is not None:
        admin_record = session.exec(
            select(AdminUser).where(AdminUser.email == normalized_email, AdminUser.is_active.is_(True))
        ).first()

    if admin_record is None:
        if normalized_email != settings.admin_email.strip().lower():
            _login_throttle.register_failure(key)
            logger.info("Admin login failed for %s", normalized_email)
            _record_login_failure(
                request,
                normalized_email,
                "unknown_account",
                session=session,
            )
            return LoginResult(False, "Invalid credentials")

        if not verify_password_hash(settings.admin_password_hash, password):
            _login_throttle.register_failure(key)
            logger.info("Admin login failed for %s", normalized_email)
            _record_login_failure(
                request,
                normalized_email,
                "invalid_credentials",
                session=session,
            )
            return LoginResult(False, "Invalid credentials")

        totp_secret = settings.admin_totp_secret or None
        session_permissions = ["*"]
        session_role = "superadmin"
        if settings.admin_hardware_fingerprints:
            normalized_assertion = (hardware_assertion or "").strip().lower()
            allowed = {fingerprint.strip().lower() for fingerprint in settings.admin_hardware_fingerprints if fingerprint}
            if normalized_assertion not in allowed:
                _login_throttle.register_failure(key)
                logger.info(
                    "Admin login failed due to missing hardware assertion for %s", normalized_email
                )
                _record_login_failure(
                    request,
                    normalized_email,
                    "hardware_assertion_required",
                    session=session,
                )
                return LoginResult(False, "Hardware security key required")
    else:
        if not verify_password_hash(admin_record.password_hash, password):
            _login_throttle.register_failure(key)
            logger.info("Admin login failed for %s", normalized_email)
            _record_login_failure(
                request,
                normalized_email,
                "invalid_credentials",
                session=session,
            )
            return LoginResult(False, "Invalid credentials")
        totp_secret = admin_record.totp_secret
        session_permissions = list(admin_record.permissions or [])
        session_role = admin_record.role

        if not identity.verify_hardware_assertion(admin_record, hardware_assertion):
            _login_throttle.register_failure(key)
            logger.info("Admin login failed due to missing hardware assertion for %s", normalized_email)
            _record_login_failure(
                request,
                normalized_email,
                "hardware_assertion_required",
                session=session,
            )
            return LoginResult(False, "Hardware security key required")

    if not _verify_totp(totp_code, override_secret=totp_secret):
        _login_throttle.register_failure(key)
        logger.info("Admin login failed due to invalid TOTP for %s", normalized_email)
        _record_login_failure(
            request,
            normalized_email,
            "invalid_totp",
            session=session,
        )
        return LoginResult(False, "Invalid authentication code")

    _login_throttle.reset(key)
    request.session["authed"] = True
    request.session["admin_email"] = normalized_email
    request.session["authenticated_at"] = datetime.now(tz=UTC).isoformat()
    request.session["permissions"] = session_permissions
    request.session["role"] = session_role
    logger.info("Admin user logged in from %s", _client_ip(request))
    record_admin_event(
        "auth.login",
        actor=normalized_email,
        ip_address=_client_ip(request),
        metadata={"user_agent": request.headers.get("user-agent", "")[:255]},
        session=session,
    )
    if session is not None:
        if admin_record:
            admin_record.last_login_at = datetime.now(tz=UTC)
            session.add(admin_record)
        session.commit()
    return LoginResult(True)


def logout(request: Request) -> RedirectResponse:
    """Clear the session and redirect to the landing page."""

    actor = request.session.get("admin_email", settings.admin_email)
    record_admin_event("auth.logout", actor=actor, ip_address=_client_ip(request))
    request.session.clear()
    return RedirectResponse("/", status_code=303)


__all__ = [
    "LoginResult",
    "configure_security",
    "has_permission",
    "login",
    "logout",
    "refresh_session_permissions",
    "session_identity",
    "SessionIdentity",
    "require_login",
    "require_permission",
    "verify_password_hash",
]
