import pytest

from app import config
from app import secret_manager


def test_normalize_base32_secret_pads_and_validates():
    assert config.normalize_base32_secret("abcd") == "ABCD===="
    with pytest.raises(ValueError):
        config.normalize_base32_secret("abcde1")


def test_settings_strict_requires_managed_secret_refs(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("BASE_URL", "http://example.com")

    with pytest.raises(config.SettingsValidationError) as excinfo:
        config.Settings().ensure_valid(strict=True)

    message = str(excinfo.value)
    assert "BASE_URL must use https" in message
    assert "SESSION_SECRET_REF" in message


def test_settings_strict_accepts_managed_secret_refs(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("BASE_URL", "https://pay.example.com")
    monkeypatch.setenv("SESSION_HTTPS_ONLY", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@db.example.com/nudgepay")

    secret_values = {
        "SESSION_SECRET": ("aws-secrets://prod/session", "s" * 32),
        "CRON_SECRET": ("aws-secrets://prod/cron", "c" * 12),
        "CRON_HMAC_SECRET": ("aws-secrets://prod/cron-hmac", "h" * 16),
        "CSRF_SECRET": ("aws-secrets://prod/csrf", "x" * 32),
        "SERVICE_TOKEN_PEPPER": ("aws-secrets://prod/pepper", "p" * 32),
        "ADMIN_PASSWORD_HASH": ("aws-secrets://prod/admin-password", "$2b$12$" + "a" * 53),
        "ADMIN_TOTP_SECRET": ("aws-secrets://prod/admin-totp", "JBSWY3DPEHPK3PXP"),
        "STRIPE_SECRET_KEY": ("aws-secrets://prod/stripe-key", "sk_test_1234567890"),
        "STRIPE_WEBHOOK_SECRET": ("aws-secrets://prod/stripe-webhook", "whsec_1234567890"),
    }

    for env_name, (ref, value) in secret_values.items():
        monkeypatch.setenv(env_name, value)
        ref_env = f"{env_name}_REF"
        monkeypatch.setenv(ref_env, ref)

    settings = config.Settings()
    result = settings.ensure_valid(strict=True)

    assert result.errors == ()
    assert result.warnings == ()


def test_resolve_managed_secret_uses_fallback(monkeypatch):
    monkeypatch.setenv("NUDGPAY_SECRET_STORE_FALLBACKS", "1")
    monkeypatch.setenv("NUDGPAY_TEST_SECRET", "placeholder")

    spec = "env://NUDGPAY_TEST_SECRET"
    secret_manager.update_managed_secret(spec, "hunter2")

    resolved = secret_manager.resolve_managed_secret(spec)

    assert resolved.value == "hunter2"
    assert resolved.metadata["provider"] == "env"
