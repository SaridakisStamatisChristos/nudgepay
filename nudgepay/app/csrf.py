"""CSRF protection utilities."""

from __future__ import annotations

import secrets
from typing import Iterable

import time

from itsdangerous import BadSignature, TimestampSigner
from starlette.requests import Request

from .config import get_settings

_SESSION_KEY = "_csrf_token"
_SESSION_ROTATION_KEY = "_csrf_rotated_at"
_COOKIE_NAME = "nudgepay_csrf"


def _signer() -> TimestampSigner:
    settings = get_settings()
    return TimestampSigner(settings.csrf_secret)


def _session(request: Request) -> dict | None:
    try:
        return request.session
    except AssertionError:  # SessionMiddleware not installed
        return None


def issue_csrf_token(request: Request) -> str:
    """Return a signed CSRF token for the current session."""

    signer = _signer()
    settings = get_settings()
    session = _session(request)
    if session is not None:
        token = session.get(_SESSION_KEY)
        rotation_interval = getattr(settings, "csrf_rotation_interval_seconds", 0)
        last_rotated = session.get(_SESSION_ROTATION_KEY, 0.0)
        should_rotate = rotation_interval > 0 and (time.time() - float(last_rotated)) >= rotation_interval
        if not token or should_rotate:
            token = secrets.token_urlsafe(32)
            session[_SESSION_KEY] = token
            session[_SESSION_ROTATION_KEY] = time.time()
        else:
            session.setdefault(_SESSION_ROTATION_KEY, time.time())
        return signer.sign(token).decode("utf-8")

    cookie_token = request.cookies.get(_COOKIE_NAME)
    if cookie_token:
        try:
            signer.unsign(cookie_token, max_age=settings.csrf_token_ttl_seconds)
        except BadSignature:
            pass
        else:
            return cookie_token

    token = secrets.token_urlsafe(32)
    return signer.sign(token).decode("utf-8")


def render_csrf_input(request: Request) -> str:
    """Return an HTML input element embedding the CSRF token."""

    token = getattr(request.state, "csrf_token", None) or issue_csrf_token(request)
    return f'<input type="hidden" name="_csrf_token" value="{token}">'  # noqa: S308


def validate_csrf_token(request: Request, token_candidates: Iterable[str | None]) -> None:
    """Validate that one of the provided tokens matches the stored secret."""

    settings = get_settings()
    session = _session(request)
    signer = _signer()
    stored: str | None
    if session is not None:
        stored = session.get(_SESSION_KEY)
        if not stored:
            raise PermissionError("Missing session CSRF secret")
    else:
        stored = None

    for candidate in token_candidates:
        if not candidate:
            continue
        try:
            value = signer.unsign(candidate, max_age=settings.csrf_token_ttl_seconds)
        except BadSignature:
            continue
        decoded = value.decode("utf-8")
        if stored is None or decoded == stored:
            if session is not None and getattr(settings, "csrf_rotation_interval_seconds", 0) > 0:
                session[_SESSION_ROTATION_KEY] = time.time()
            return
    raise PermissionError("Invalid CSRF token")


def force_rotate_csrf_token(request: Request) -> str:
    """Invalidate the current CSRF secret and issue a replacement."""

    session = _session(request)
    if session is not None:
        session.pop(_SESSION_KEY, None)
        session[_SESSION_ROTATION_KEY] = 0.0
    return issue_csrf_token(request)


__all__ = [
    "_COOKIE_NAME",
    "force_rotate_csrf_token",
    "issue_csrf_token",
    "render_csrf_input",
    "validate_csrf_token",
]
