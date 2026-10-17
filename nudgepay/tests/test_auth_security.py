import base64
import hashlib
import hmac
import json
import struct
import time

import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlmodel import select

from app import main
from app.auth import configure_security
from app.config import get_settings, normalize_base32_secret, reset_settings_cache
from app.db import init_db, session_scope
from app.models import AdminAuditLog


def _csrf_token(client: TestClient) -> str:
    response = client.get("/login", follow_redirects=True)
    header_token = response.headers.get("X-CSRF-Token")
    if header_token:
        return header_token

    marker = 'name="_csrf_token" value="'
    html = response.text
    start = html.find(marker)
    assert start != -1, "CSRF token not found in login form"
    start += len(marker)
    end = html.find('"', start)
    assert end != -1, "Malformed CSRF input"
    return html[start:end]


def _configure_app(monkeypatch, **env_overrides):
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, value)
    reset_settings_cache()
    new_settings = get_settings()
    main.settings = new_settings
    main.app.state.settings = new_settings
    configure_security(new_settings)
    init_db()
    with session_scope() as session:
        session.exec(delete(AdminAuditLog))
        session.commit()
    return TestClient(main.app, base_url="https://testserver"), new_settings


@pytest.fixture(autouse=True)
def restore_defaults():
    yield
    reset_settings_cache()
    default_settings = get_settings()
    main.settings = default_settings
    main.app.state.settings = default_settings
    configure_security(default_settings)


def test_login_rate_limited(monkeypatch):
    password = "Sup3rSecure!"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    client, _ = _configure_app(
        monkeypatch,
        ADMIN_EMAIL="owner@example.com",
        ADMIN_PASSWORD_HASH=hashed,
        LOGIN_RATE_LIMIT_ATTEMPTS="2",
        LOGIN_RATE_LIMIT_WINDOW_SECONDS="60",
        LOGIN_RATE_LIMIT_BLOCK_SECONDS="1",
    )

    token = _csrf_token(client)

    for _ in range(2):
        resp = client.post(
            "/login",
            data={"email": "owner@example.com", "password": "wrong", "_csrf_token": token},
            headers={"X-CSRF-Token": token},
        )
        assert resp.status_code == 200
        assert b"Invalid credentials" in resp.content

    token = _csrf_token(client)
    third = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "wrong", "_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert third.status_code == 429
    assert b"Too many attempts" in third.content
    retry_after = third.headers.get("retry-after")
    assert retry_after is not None
    assert int(retry_after) >= 0

    time.sleep(1.1)
    token = _csrf_token(client)
    success = client.post(
        "/login",
        data={"email": "owner@example.com", "password": password, "_csrf_token": token},
        headers={"X-CSRF-Token": token},
        follow_redirects=True,
    )
    assert success.status_code in (200, 303)

    with session_scope() as session:
        audit_entries = session.exec(
            select(AdminAuditLog).where(AdminAuditLog.action == "auth.login")
        ).all()
        assert audit_entries, "Login should be captured in the audit log"
        rate_limited = session.exec(
            select(AdminAuditLog).where(AdminAuditLog.action == "auth.login_rate_limited")
        ).all()
        assert rate_limited, "Rate-limited attempts must be captured in the audit log"


def test_login_failure_is_audited(monkeypatch):
    password = "Sup3rSecure!"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    client, _ = _configure_app(
        monkeypatch,
        ADMIN_EMAIL="owner@example.com",
        ADMIN_PASSWORD_HASH=hashed,
    )

    token = _csrf_token(client)
    failure = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "wrong", "_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert failure.status_code == 200
    assert b"Invalid credentials" in failure.content

    with session_scope() as session:
        entries = session.exec(
            select(AdminAuditLog).where(AdminAuditLog.action == "auth.login_failed")
        ).all()
        assert entries, "Failed logins should be captured in the audit log"
        context = json.loads(entries[-1].context)
        assert context.get("reason") == "invalid_credentials"


def test_login_requires_totp(monkeypatch):
    password = "Sup3rSecure!"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    secret = "nb2w 45df oiza"
    client, _ = _configure_app(
        monkeypatch,
        ADMIN_EMAIL="owner@example.com",
        ADMIN_PASSWORD_HASH=hashed,
        ADMIN_TOTP_SECRET=secret,
    )

    form = client.get("/login")
    assert form.status_code == 200
    assert b"Authentication code" in form.content

    token = _csrf_token(client)
    missing_totp = client.post(
        "/login",
        data={"email": "owner@example.com", "password": password, "_csrf_token": token},
        headers={"X-CSRF-Token": token},
    )
    assert missing_totp.status_code == 200
    assert b"Invalid authentication code" in missing_totp.content

    code = _generate_totp_code(secret)
    token = _csrf_token(client)
    success = client.post(
        "/login",
        data={
            "email": "owner@example.com",
            "password": password,
            "totp_code": code,
            "_csrf_token": token,
        },
        headers={"X-CSRF-Token": token},
        follow_redirects=True,
    )
    assert success.status_code in (200, 303)

    with session_scope() as session:
        audit_entries = session.exec(
            select(AdminAuditLog).where(AdminAuditLog.action == "auth.login")
        ).all()
        assert audit_entries
def _generate_totp_code(secret: str, *, timestamp: int | None = None) -> str:
    ts = int(time.time() if timestamp is None else timestamp)
    counter = ts // 30
    normalized = normalize_base32_secret(secret)
    key = base64.b32decode(normalized, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = digest[offset : offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF
    return f"{code_int % 1_000_000:06d}"

