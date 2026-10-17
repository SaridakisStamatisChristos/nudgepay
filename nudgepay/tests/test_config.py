from __future__ import annotations

from pathlib import Path

import pytest

from app import config


def teardown_function() -> None:
    config.reset_settings_cache()


def test_settings_loads_secret_from_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_path = tmp_path / "session.key"
    expected_secret = "super-secret"
    secret_path.write_text(f"{expected_secret}\n", encoding="utf-8")

    monkeypatch.setenv("SESSION_SECRET_REF", "env://SESSION_SECRET_VALUE")
    monkeypatch.setenv("SESSION_SECRET_VALUE", "super-secret-session-key-please-rotate")
    monkeypatch.setenv("SESSION_SECRET_FILE", str(secret_path))
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    config.reset_settings_cache()
    settings = config.get_settings()
    assert settings.session_secret == expected_secret


def test_settings_accepts_unpadded_totp_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADMIN_TOTP_SECRET", "nb2w 45df oiza")
    monkeypatch.setenv("ADMIN_TOTP_SECRET_REF", "env://ADMIN_TOTP_SECRET_VALUE")
    monkeypatch.setenv("ADMIN_TOTP_SECRET_VALUE", "JBSWY3DPEHPK3PXP")

    config.reset_settings_cache()
    settings = config.get_settings()
    assert settings.admin_totp_secret == "nb2w 45df oiza"
    result = settings.validate()

    assert all(
        "Admin TOTP secret must be a valid base32 string." not in message
        for message in result.errors
    )


def test_settings_validation_captures_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASE_URL", "ftp://example.com")
    monkeypatch.setenv("ADMIN_EMAIL", "not-an-email")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "plain-text")
    monkeypatch.setenv("SESSION_COOKIE_SAME_SITE", "invalid")
    monkeypatch.setenv("SMTP_PORT", "-1")
    monkeypatch.setenv("LOG_LEVEL", "NOTALEVEL")
    monkeypatch.setenv("ADMIN_TOTP_SECRET", "not-base32")
    monkeypatch.setenv("LOGIN_RATE_LIMIT_ATTEMPTS", "0")
    monkeypatch.setenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "0")
    monkeypatch.setenv("LOGIN_RATE_LIMIT_BLOCK_SECONDS", "0")

    config.reset_settings_cache()
    settings = config.get_settings()
    result = settings.validate()

    expectations = {
        "Base URL must be http or https.",
        "Admin email must be a valid email address.",
        "Admin password hash must be a bcrypt hash string.",
        "Session cookie same-site policy must be lax, strict, or none.",
        "SMTP port must be between 1 and 65535.",
        "Log level must be a valid logging level name.",
        "Admin TOTP secret must be a valid base32 string.",
        "Login rate limit attempts must be positive.",
        "Login rate limit window must be positive.",
        "Login rate limit block must be positive.",
    }

    for message in expectations:
        assert any(message in error for error in result.errors), message


def test_settings_enforce_strict_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SESSION_SECRET", "short")
    monkeypatch.setenv("CRON_SECRET", "tiny")

    config.reset_settings_cache()
    settings = config.get_settings()

    with pytest.raises(config.SettingsValidationError):
        settings.ensure_valid()
