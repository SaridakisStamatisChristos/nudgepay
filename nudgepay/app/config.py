"""Application configuration helpers."""

from __future__ import annotations

import base64
import binascii
import logging
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlparse

from .secret_manager import SecretResolutionError, resolve_managed_secret


class SettingsValidationError(RuntimeError):
    """Raised when the configuration is invalid for the current environment."""


@dataclass(frozen=True)
class SettingsValidationResult:
    """Represents the outcome of validating the runtime settings."""

    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def is_clean(self) -> bool:
        """Return ``True`` when no warnings or errors were produced."""

        return not self.errors and not self.warnings


def _env_bool(value: str | None, *, default: bool = False) -> bool:
    """Coerce an environment variable to a boolean value."""

    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: str | None, *, default: tuple[str, ...]) -> tuple[str, ...]:
    """Split a comma separated value into a tuple."""

    if not value:
        return default
    items = tuple(item.strip() for item in value.split(",") if item.strip())
    return items or default


_SECRET_PROVIDER_PREFIXES = (
    "aws-secrets://",
    "vault://",
    "gcp-sm://",
    "env://",
)


_BASE32_PADDING_MAP = {0: 0, 2: 6, 4: 4, 5: 3, 7: 1}


def normalize_base32_secret(value: str) -> str:
    """Return a padded, uppercase base32 string suitable for decoding."""

    compact = "".join(value.split()).upper().rstrip("=")
    if not compact:
        return ""
    remainder = len(compact) % 8
    if remainder not in _BASE32_PADDING_MAP:
        raise ValueError("Invalid base32 length")
    padding = _BASE32_PADDING_MAP[remainder]
    return compact + ("=" * padding)


def _is_managed_secret(value: str | None) -> bool:
    if not value:
        return False
    return value.startswith(_SECRET_PROVIDER_PREFIXES)


def _load_secret(env_name: str, default: str = "") -> str:
    """Load a secret from ``ENV_NAME`` or ``ENV_NAME_FILE``."""

    file_path = os.getenv(f"{env_name}_FILE")
    if file_path:
        try:
            value = Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as exc:  # pragma: no cover - system dependent
            raise SettingsValidationError(
                f"Failed reading secret file for {env_name}: {exc}"
            ) from exc
        if value:
            return value

    direct_value = os.getenv(env_name)
    if direct_value is not None:
        candidate = direct_value.strip()
        if candidate:
            for prefix in _SECRET_PROVIDER_PREFIXES:
                if candidate.startswith(prefix):
                    try:
                        resolved = resolve_managed_secret(candidate).value.strip()
                    except (
                        SecretResolutionError
                    ) as exc:  # pragma: no cover - runtime configuration issue
                        raise SettingsValidationError(str(exc)) from exc
                    return resolved
            return candidate

    reference = os.getenv(f"{env_name}_REF")
    if reference:
        try:
            value = resolve_managed_secret(reference).value.strip()
        except (
            SecretResolutionError
        ) as exc:  # pragma: no cover - runtime configuration issue
            raise SettingsValidationError(str(exc)) from exc
        if value:
            return value

    fallback = default.strip()
    for prefix in _SECRET_PROVIDER_PREFIXES:
        if fallback.startswith(prefix):
            try:
                return resolve_managed_secret(fallback).value.strip()
            except (
                SecretResolutionError
            ) as exc:  # pragma: no cover - runtime configuration issue
                raise SettingsValidationError(str(exc)) from exc

    return fallback


_VALID_ENVIRONMENTS = MappingProxyType(
    {env: env for env in ("development", "test", "staging", "production")}
)


_DEV_SENTINELS = MappingProxyType(
    {
        "session_secret": "dev_secret_key_change_me",
        "cron_secret": "dev_cron_secret",
        "cron_hmac_secret": "dev_cron_hmac",
        "csrf_secret": "dev_csrf_secret_change_me",
        "service_token_pepper": "dev_service_token_pepper",
        "admin_password_hash": "$2b$12$1r6i1mS8Z2s8oGJ8o3bFxe6b1F2f.9f8QF9oJfUVr0v3/Lz8aZ1Q6",
    }
)

_SENSITIVE_SECRET_REFS = (
    "SESSION_SECRET_REF",
    "CRON_SECRET_REF",
    "CRON_HMAC_SECRET_REF",
    "SERVICE_TOKEN_PEPPER_REF",
    "ADMIN_PASSWORD_HASH_REF",
    "ADMIN_TOTP_SECRET_REF",
    "STRIPE_SECRET_KEY_REF",
    "STRIPE_WEBHOOK_SECRET_REF",
)

_MANAGED_SECRET_ATTRS = (
    ("session_secret_ref", "SESSION_SECRET_REF"),
    ("cron_secret_ref", "CRON_SECRET_REF"),
    ("cron_hmac_secret_ref", "CRON_HMAC_SECRET_REF"),
    ("service_token_pepper_ref", "SERVICE_TOKEN_PEPPER_REF"),
    ("admin_password_hash_ref", "ADMIN_PASSWORD_HASH_REF"),
    ("admin_totp_secret_ref", "ADMIN_TOTP_SECRET_REF"),
    ("stripe_secret_key_ref", "STRIPE_SECRET_KEY_REF"),
    ("stripe_webhook_secret_ref", "STRIPE_WEBHOOK_SECRET_REF"),
)


@dataclass(frozen=True)
class Settings:
    """Container for all runtime configuration."""

    environment: str = field(
        default_factory=lambda: os.getenv("ENVIRONMENT", "development").strip().lower()
    )
    base_url: str = field(
        default_factory=lambda: os.getenv("BASE_URL", "http://localhost:8000")
    )
    session_secret: str = field(
        default_factory=lambda: _load_secret(
            "SESSION_SECRET", "dev_secret_key_change_me"
        )
    )
    session_secret_ref: str | None = field(
        default_factory=lambda: (os.getenv("SESSION_SECRET_REF") or None)
    )
    cron_secret: str = field(
        default_factory=lambda: _load_secret("CRON_SECRET", "dev_cron_secret")
    )
    cron_secret_ref: str | None = field(
        default_factory=lambda: (os.getenv("CRON_SECRET_REF") or None)
    )
    cron_hmac_secret: str = field(
        default_factory=lambda: _load_secret("CRON_HMAC_SECRET", "dev_cron_hmac")
    )
    cron_hmac_secret_ref: str | None = field(
        default_factory=lambda: (os.getenv("CRON_HMAC_SECRET_REF") or None)
    )
    cron_signature_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("CRON_SIGNATURE_TTL_SECONDS", "300"))
    )
    cron_mutual_tls_required: bool = field(
        default_factory=lambda: _env_bool(os.getenv("CRON_MUTUAL_TLS_REQUIRED"))
    )
    cron_mutual_tls_fingerprints: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(
            os.getenv("CRON_MUTUAL_TLS_FINGERPRINTS"),
            default=(),
        )
    )
    session_https_only: bool = field(
        default_factory=lambda: _env_bool(os.getenv("SESSION_HTTPS_ONLY"))
    )
    session_cookie_name: str = field(
        default_factory=lambda: os.getenv("SESSION_COOKIE_NAME", "nudgepay_session")
    )
    session_cookie_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SESSION_COOKIE_TTL_SECONDS", "1209600"))
    )
    session_cookie_same_site: str = field(
        default_factory=lambda: os.getenv("SESSION_COOKIE_SAME_SITE", "lax")
    )
    admin_email: str = field(
        default_factory=lambda: os.getenv("ADMIN_EMAIL", "admin@example.com")
    )
    admin_password_hash: str = field(
        default_factory=lambda: _load_secret(
            "ADMIN_PASSWORD_HASH",
            "$2b$12$1r6i1mS8Z2s8oGJ8o3bFxe6b1F2f.9f8QF9oJfUVr0v3/Lz8aZ1Q6",
        )
    )
    admin_password_hash_ref: str | None = field(
        default_factory=lambda: (os.getenv("ADMIN_PASSWORD_HASH_REF") or None)
    )
    admin_totp_secret: str = field(
        default_factory=lambda: _load_secret("ADMIN_TOTP_SECRET", "")
    )
    admin_totp_secret_ref: str | None = field(
        default_factory=lambda: (os.getenv("ADMIN_TOTP_SECRET_REF") or None)
    )
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./nudgpay.db")
    )
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    task_queue_name: str = field(
        default_factory=lambda: os.getenv("TASK_QUEUE_NAME", "nudgepay")
    )
    csrf_secret: str = field(
        default_factory=lambda: _load_secret("CSRF_SECRET", "dev_csrf_secret_change_me")
    )
    csrf_token_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("CSRF_TOKEN_TTL_SECONDS", "3600"))
    )
    csrf_rotation_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("CSRF_ROTATION_INTERVAL_SECONDS", "1800"))
    )
    csrf_exempt_paths: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(
            os.getenv("CSRF_EXEMPT_PATHS"),
            default=("/internal/run-reminders", "/webhooks/stripe"),
        )
    )
    stripe_secret_key: str = field(
        default_factory=lambda: _load_secret("STRIPE_SECRET_KEY", "")
    )
    stripe_secret_key_ref: str | None = field(
        default_factory=lambda: (os.getenv("STRIPE_SECRET_KEY_REF") or None)
    )
    stripe_webhook_secret: str = field(
        default_factory=lambda: _load_secret("STRIPE_WEBHOOK_SECRET", "")
    )
    stripe_webhook_secret_ref: str | None = field(
        default_factory=lambda: (os.getenv("STRIPE_WEBHOOK_SECRET_REF") or None)
    )
    stripe_webhook_additional_secrets: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(
            os.getenv("STRIPE_WEBHOOK_ADDITIONAL_SECRETS"),
            default=(),
        )
    )
    webhook_shared_secret: str = field(
        default_factory=lambda: _load_secret("WEBHOOK_SHARED_SECRET", "")
    )
    stripe_webhook_allowed_events: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(
            os.getenv("STRIPE_WEBHOOK_ALLOWED_EVENTS"),
            default=("payment_intent.succeeded", "checkout.session.completed"),
        )
    )
    stripe_webhook_circuit_threshold: int = field(
        default_factory=lambda: int(os.getenv("STRIPE_WEBHOOK_CIRCUIT_THRESHOLD", "5"))
    )
    stripe_webhook_circuit_ttl_seconds: int = field(
        default_factory=lambda: int(
            os.getenv("STRIPE_WEBHOOK_CIRCUIT_TTL_SECONDS", "900")
        )
    )
    stripe_product_name: str = field(
        default_factory=lambda: os.getenv("STRIPE_PRODUCT_NAME", "Invoice Payment")
    )
    smtp_host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", "localhost"))
    smtp_port: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "1025")))
    smtp_user: str | None = field(default=None)
    smtp_pass: str | None = field(default=None)
    from_email: str = field(
        default_factory=lambda: os.getenv("FROM_EMAIL", "noreply@nudgepay.app")
    )
    debug: bool = field(default_factory=lambda: _env_bool(os.getenv("DEBUG")))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    hsts_seconds: int = field(
        default_factory=lambda: int(os.getenv("HSTS_SECONDS", "0"))
    )
    content_security_policy: str = field(
        default_factory=lambda: os.getenv(
            "CONTENT_SECURITY_POLICY",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
        )
    )
    request_id_header: str = field(
        default_factory=lambda: os.getenv("REQUEST_ID_HEADER", "X-Request-ID")
    )
    allowed_hosts: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(os.getenv("ALLOWED_HOSTS"), default=("*",))
    )
    cors_origins: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(os.getenv("CORS_ORIGINS"), default=())
    )
    metrics_enabled: bool = field(
        default_factory=lambda: _env_bool(os.getenv("METRICS_ENABLED"), default=True)
    )
    metrics_endpoint: str = field(
        default_factory=lambda: os.getenv("METRICS_ENDPOINT", "/metrics")
    )
    metrics_prefix: str = field(
        default_factory=lambda: os.getenv("METRICS_PREFIX", "nudgepay")
    )
    metrics_export_endpoint: str | None = field(
        default_factory=lambda: (os.getenv("METRICS_EXPORT_ENDPOINT") or None)
    )
    metrics_export_api_key: str | None = field(
        default_factory=lambda: (_load_secret("METRICS_EXPORT_API_KEY") or None)
    )
    login_rate_limit_attempts: int = field(
        default_factory=lambda: int(os.getenv("LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
    )
    login_rate_limit_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300"))
    )
    login_rate_limit_block_seconds: int = field(
        default_factory=lambda: int(os.getenv("LOGIN_RATE_LIMIT_BLOCK_SECONDS", "900"))
    )
    dlq_reprocessor_schedule: str = field(
        default_factory=lambda: os.getenv("DLQ_REPROCESSOR_SCHEDULE", "*/10 * * * *")
    )
    dlq_reprocessor_batch_size: int = field(
        default_factory=lambda: int(os.getenv("DLQ_REPROCESSOR_BATCH_SIZE", "100"))
    )
    backup_verification_schedule: str = field(
        default_factory=lambda: os.getenv("BACKUP_VERIFICATION_SCHEDULE", "30 2 * * *")
    )
    backup_verification_glob: str = field(
        default_factory=lambda: os.getenv("BACKUP_VERIFICATION_GLOB", "backups/*")
    )
    secret_rotation_schedule: str = field(
        default_factory=lambda: os.getenv("SECRET_ROTATION_SCHEDULE", "0 6 * * *")
    )
    secret_rotation_hook_urls: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(
            os.getenv("SECRET_ROTATION_HOOK_URLS"), default=()
        )
    )
    secret_rotation_grace_seconds: int = field(
        default_factory=lambda: int(os.getenv("SECRET_ROTATION_GRACE_SECONDS", "900"))
    )
    secret_rotation_runbook_template: str | None = field(
        default_factory=lambda: (os.getenv("SECRET_ROTATION_RUNBOOK_TEMPLATE") or None)
    )
    secret_rotation_dashboard_template: str | None = field(
        default_factory=lambda: (
            os.getenv("SECRET_ROTATION_DASHBOARD_TEMPLATE") or None
        )
    )
    webhook_secret_rotation_schedule: str = field(
        default_factory=lambda: os.getenv(
            "WEBHOOK_SECRET_ROTATION_SCHEDULE", "30 1 * * *"
        )
    )
    schema_rehearsal_schedule: str = field(
        default_factory=lambda: os.getenv("SCHEMA_REHEARSAL_SCHEDULE", "0 4 * * 0")
    )
    schema_rehearsal_downgrade_target: str = field(
        default_factory=lambda: os.getenv("SCHEMA_REHEARSAL_DOWNGRADE_TARGET", "base")
    )
    chaos_game_day_schedule: str = field(
        default_factory=lambda: os.getenv("CHAOS_GAME_DAY_SCHEDULE", "0 3 * * 1")
    )
    automation_scheduler_target: str = field(
        default_factory=lambda: os.getenv(
            "AUTOMATION_SCHEDULER_TARGET", "github-actions"
        )
    )
    automation_pagerduty_service: str | None = field(
        default_factory=lambda: (os.getenv("AUTOMATION_PAGERDUTY_SERVICE") or None)
    )
    automation_pagerduty_routing_key: str | None = field(
        default_factory=lambda: (
            _load_secret("AUTOMATION_PAGERDUTY_ROUTING_KEY") or None
        )
    )
    automation_slack_channel: str | None = field(
        default_factory=lambda: (os.getenv("AUTOMATION_SLACK_CHANNEL") or None)
    )
    automation_slack_webhook: str | None = field(
        default_factory=lambda: (_load_secret("AUTOMATION_SLACK_WEBHOOK") or None)
    )
    automation_email_recipients: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(
            os.getenv("AUTOMATION_EMAIL_RECIPIENTS"), default=()
        )
    )
    admin_hardware_fingerprints: tuple[str, ...] = field(
        default_factory=lambda: _split_csv(
            os.getenv("ADMIN_HARDWARE_FINGERPRINTS"),
            default=(),
        )
    )
    webhook_secret_rotation_days: int = field(
        default_factory=lambda: int(os.getenv("WEBHOOK_SECRET_ROTATION_DAYS", "30"))
    )
    webhook_secret_overlap_seconds: int = field(
        default_factory=lambda: int(os.getenv("WEBHOOK_SECRET_OVERLAP_SECONDS", "3600"))
    )
    environment_seed_dataset: str | None = field(
        default_factory=lambda: (os.getenv("ENVIRONMENT_SEED_DATASET") or None)
    )
    service_token_pepper: str = field(
        default_factory=lambda: _load_secret(
            "SERVICE_TOKEN_PEPPER", "dev_service_token_pepper"
        )
    )
    service_token_pepper_ref: str | None = field(
        default_factory=lambda: (os.getenv("SERVICE_TOKEN_PEPPER_REF") or None)
    )
    delegated_approval_ttl_minutes: int = field(
        default_factory=lambda: int(os.getenv("DELEGATED_APPROVAL_TTL_MINUTES", "1440"))
    )
    default_required_approvals: int = field(
        default_factory=lambda: int(os.getenv("DEFAULT_REQUIRED_APPROVALS", "2"))
    )

    def __post_init__(self) -> None:
        if self.environment not in _VALID_ENVIRONMENTS:
            object.__setattr__(self, "environment", "development")

        # Automatically secure cookies when hosted behind HTTPS unless explicitly overridden.
        if "SESSION_HTTPS_ONLY" not in os.environ:
            https_only = urlparse(self.base_url).scheme == "https"
            object.__setattr__(self, "session_https_only", https_only)

        same_site = self.session_cookie_same_site.lower()
        object.__setattr__(self, "session_cookie_same_site", same_site)

        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = _load_secret("SMTP_PASS", "") or None
        object.__setattr__(self, "smtp_user", smtp_user)
        object.__setattr__(self, "smtp_pass", smtp_pass)

    # ------------------------------ Validation helpers ------------------------------
    def validate(self) -> SettingsValidationResult:
        """Return validation errors and warnings for the configuration."""

        errors: list[str] = []
        warnings: list[str] = []

        is_prod_like = self.environment in {"staging", "production"}

        parsed_url = urlparse(self.base_url)
        if parsed_url.scheme not in {"http", "https"}:
            errors.append("Base URL must be http or https.")
        if not parsed_url.netloc:
            errors.append("Base URL must include a hostname.")
        if is_prod_like and parsed_url.scheme != "https":
            errors.append("BASE_URL must use https in staging and production.")

        if "@" not in self.admin_email:
            errors.append("Admin email must be a valid email address.")

        if not re.match(r"^\$2[aby]\$\d{2}\$.{53}$", self.admin_password_hash):
            errors.append("Admin password hash must be a bcrypt hash string.")

        database_url = self.database_url.strip()
        if not database_url:
            errors.append("DATABASE_URL must be configured.")
        elif database_url.startswith("sqlite"):
            message = (
                "DATABASE_URL must point to a managed PostgreSQL database, not SQLite."
            )
            if is_prod_like:
                errors.append(message)
            else:
                warnings.append(message)
        elif is_prod_like and not database_url.startswith(
            ("postgres://", "postgresql://")
        ):
            errors.append(
                "DATABASE_URL must use the postgres scheme in staging and production."
            )

        for attr, sentinel in _DEV_SENTINELS.items():
            value = getattr(self, attr, "")
            if value == sentinel:
                message = f"{attr.upper()} is using the development default; configure a managed secret."
                if is_prod_like:
                    errors.append(message)
                else:
                    warnings.append(message)

        if len(self.session_secret) < 32:
            message = "Session secret must be at least 32 characters."
            if is_prod_like:
                errors.append(message)
            else:
                warnings.append(message)

        if len(self.cron_secret) < 12:
            message = "Cron secret should be at least 12 characters."
            if is_prod_like:
                errors.append(message)
            else:
                warnings.append(message)

        if len(self.cron_hmac_secret) < 16:
            message = "Cron HMAC secret should be at least 16 characters."
            if is_prod_like:
                errors.append(message)
            else:
                warnings.append(message)

        if len(self.service_token_pepper) < 32:
            message = "Service token pepper must be at least 32 characters."
            if is_prod_like:
                errors.append(message)
            else:
                warnings.append(message)

        if self.session_cookie_same_site not in {"lax", "strict", "none"}:
            errors.append(
                "Session cookie same-site policy must be lax, strict, or none."
            )

        if self.session_cookie_same_site == "none" and not self.session_https_only:
            warnings.append("SameSite=None cookies should only be served over HTTPS.")

        if is_prod_like and not self.session_https_only:
            errors.append("SESSION_HTTPS_ONLY must be true in staging and production.")

        if not self.csrf_secret or len(self.csrf_secret) < 16:
            errors.append("CSRF secret must be set to a strong value.")

        if is_prod_like and len(self.csrf_secret) < 32:
            errors.append(
                "CSRF secret must be at least 32 characters in staging and production."
            )

        if self.session_cookie_ttl_seconds <= 0:
            errors.append("Session cookie TTL must be positive.")

        if self.smtp_port <= 0 or self.smtp_port > 65535:
            errors.append("SMTP port must be between 1 and 65535.")

        if self.from_email.count("@") != 1:
            warnings.append("From email address appears to be invalid.")

        if self.stripe_secret_key and not self.stripe_secret_key.startswith("sk_"):
            warnings.append("Stripe secret keys typically start with 'sk_'.")

        if self.stripe_webhook_secret and not self.stripe_webhook_secret.startswith(
            "whsec_"
        ):
            warnings.append("Stripe webhook secrets typically start with 'whsec_'.")

        if self.webhook_shared_secret and len(self.webhook_shared_secret) < 16:
            warnings.append("Webhook shared secret should be at least 16 characters.")

        if not self.stripe_webhook_allowed_events:
            errors.append("Stripe webhook allowed events list must not be empty.")

        if self.stripe_webhook_circuit_threshold <= 0:
            errors.append("Stripe webhook circuit threshold must be positive.")

        if self.stripe_webhook_circuit_ttl_seconds <= 0:
            errors.append("Stripe webhook circuit TTL must be positive.")

        if (
            self.log_level.upper() not in logging._nameToLevel
        ):  # noqa: SLF001 - accessing internals
            errors.append("Log level must be a valid logging level name.")

        if self.cron_signature_ttl_seconds <= 0:
            errors.append("Cron signature TTL must be positive.")

        if self.cron_mutual_tls_required and not self.cron_mutual_tls_fingerprints:
            errors.append("Cron mutual TLS requires at least one allowed fingerprint.")

        if self.admin_totp_secret:
            try:
                normalized_secret = normalize_base32_secret(self.admin_totp_secret)
                if not normalized_secret:
                    raise ValueError("Blank secret")
                base64.b32decode(normalized_secret, casefold=True)
            except (binascii.Error, ValueError, TypeError):
                errors.append("Admin TOTP secret must be a valid base32 string.")

        if self.login_rate_limit_attempts <= 0:
            errors.append("Login rate limit attempts must be positive.")

        if self.login_rate_limit_window_seconds <= 0:
            errors.append("Login rate limit window must be positive.")

        if self.login_rate_limit_block_seconds <= 0:
            errors.append("Login rate limit block must be positive.")

        if self.dlq_reprocessor_batch_size <= 0:
            errors.append("DLQ reprocessor batch size must be positive.")

        if not self.backup_verification_glob:
            errors.append("Backup verification glob must not be empty.")

        if self.webhook_secret_rotation_days <= 0:
            errors.append("Webhook secret rotation cadence must be positive days.")
        if self.webhook_secret_overlap_seconds <= 0:
            errors.append("Webhook secret overlap must be positive seconds.")
        if self.delegated_approval_ttl_minutes < 0:
            errors.append("Delegated approval TTL must be zero or greater.")
        if self.default_required_approvals <= 0:
            errors.append("Default required approvals must be positive.")
        if is_prod_like:
            for attr, env_name in _MANAGED_SECRET_ATTRS:
                ref_value = getattr(self, attr, None)
                if not _is_managed_secret(ref_value):
                    errors.append(
                        f"{env_name} must reference a managed secret provider (aws-secrets://, vault://, gcp-sm://)."
                    )

        if (
            self.automation_pagerduty_service
            and not self.automation_pagerduty_routing_key
        ):
            errors.append(
                "AUTOMATION_PAGERDUTY_ROUTING_KEY must be configured when a PagerDuty service is defined."
            )

        if self.automation_slack_channel and not self.automation_slack_webhook:
            errors.append(
                "AUTOMATION_SLACK_WEBHOOK must be configured when a Slack alert channel is defined."
            )

        if self.metrics_export_endpoint and not self.metrics_export_api_key:
            warnings.append(
                "Metrics export endpoint configured without METRICS_EXPORT_API_KEY; requests will be unauthenticated."
            )

        return SettingsValidationResult(tuple(errors), tuple(warnings))

    def ensure_valid(self, *, strict: bool | None = None) -> SettingsValidationResult:
        """Validate settings and optionally enforce a strict policy."""

        result = self.validate()
        if strict is None:
            strict = self.environment in {"staging", "production"}

        if strict and (result.errors or result.warnings):
            raise SettingsValidationError("; ".join(result.errors + result.warnings))

        return result


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""

    return Settings()


def reset_settings_cache() -> None:
    """Clear the cached settings, primarily for testing purposes."""

    get_settings.cache_clear()


__all__ = [
    "Settings",
    "SettingsValidationError",
    "SettingsValidationResult",
    "get_settings",
    "normalize_base32_secret",
    "reset_settings_cache",
]
