"""Utilities for providing deterministic CI environment defaults."""
from __future__ import annotations

import os
from typing import Mapping

# Secrets must satisfy the production/staging validators so that developers can
# run ``make ci`` locally without piping in the entire managed secret catalog.
_DEFAULT_ENV: Mapping[str, str] = {
    "BASE_URL": "https://staging.nudgepay.test",
    "SESSION_HTTPS_ONLY": "true",
    "SESSION_SECRET": "env://SESSION_SECRET_VALUE",
    "SESSION_SECRET_REF": "env://SESSION_SECRET_VALUE",
    "SESSION_SECRET_VALUE": "ci-session-secret-value-0123456789abcdef0123456789abcdef",
    "CRON_SECRET": "env://CRON_SECRET_VALUE",
    "CRON_SECRET_REF": "env://CRON_SECRET_VALUE",
    "CRON_SECRET_VALUE": "ci-cron-secret-value-1234567890",
    "CRON_HMAC_SECRET": "env://CRON_HMAC_SECRET_VALUE",
    "CRON_HMAC_SECRET_REF": "env://CRON_HMAC_SECRET_VALUE",
    "CRON_HMAC_SECRET_VALUE": "ci-cron-hmac-secret-value-123456",
    "SERVICE_TOKEN_PEPPER": "env://SERVICE_TOKEN_PEPPER_VALUE",
    "SERVICE_TOKEN_PEPPER_REF": "env://SERVICE_TOKEN_PEPPER_VALUE",
    "SERVICE_TOKEN_PEPPER_VALUE": (
        "ci-service-token-pepper-value-0123456789abcdef0123456789abcdef"
    ),
    "ADMIN_PASSWORD_HASH": "env://ADMIN_PASSWORD_HASH_VALUE",
    "ADMIN_PASSWORD_HASH_REF": "env://ADMIN_PASSWORD_HASH_VALUE",
    "ADMIN_PASSWORD_HASH_VALUE": (
        "$2b$12$Y9mx6GP.n7i/9nCzHK8xteN.1gPlwFMv6Jr9gdSKS9kFMOy.k1r1W"
    ),
    "ADMIN_TOTP_SECRET": "env://ADMIN_TOTP_SECRET_VALUE",
    "ADMIN_TOTP_SECRET_REF": "env://ADMIN_TOTP_SECRET_VALUE",
    "ADMIN_TOTP_SECRET_VALUE": "JBSWY3DPEHPK3PXP",
    "CSRF_SECRET": "env://CSRF_SECRET_VALUE",
    "CSRF_SECRET_VALUE": "ci-csrf-secret-value-0123456789abcdef",
    "STRIPE_SECRET_KEY": "env://STRIPE_SECRET_KEY_VALUE",
    "STRIPE_SECRET_KEY_REF": "env://STRIPE_SECRET_KEY_VALUE",
    "STRIPE_SECRET_KEY_VALUE": "sk_test_ci_secret_key_0123456789abcdef",
    "STRIPE_WEBHOOK_SECRET": "env://STRIPE_WEBHOOK_SECRET_VALUE",
    "STRIPE_WEBHOOK_SECRET_REF": "env://STRIPE_WEBHOOK_SECRET_VALUE",
    "STRIPE_WEBHOOK_SECRET_VALUE": "whsec_ci_secret_key_0123456789abcdef",
    "DATABASE_URL": "postgresql://postgres:postgres@localhost:5432/postgres",
    "AUTOMATION_PAGERDUTY_ROUTING_KEY": "ci-routing-key",
    "AUTOMATION_PAGERDUTY_ROUTING_KEY_REF": "env://AUTOMATION_PAGERDUTY_ROUTING_KEY_VALUE",
    "AUTOMATION_PAGERDUTY_ROUTING_KEY_VALUE": "ci-routing-key",
    "AUTOMATION_SLACK_WEBHOOK": "https://hooks.slack.com/services/T000/B000/CIHOOK",
    "AUTOMATION_SLACK_WEBHOOK_REF": "env://AUTOMATION_SLACK_WEBHOOK_VALUE",
    "AUTOMATION_SLACK_WEBHOOK_VALUE": "https://hooks.slack.com/services/T000/B000/CIHOOK",
}


def apply_ci_environment_defaults() -> None:
    """Populate environment variables required for release gates.

    Real CI (GitHub Actions) will provide production-like values via secrets, so
    we only supply defaults when a variable is absent. The placeholders are long
    enough to satisfy validation but contain no sensitive information.
    """

    for key, value in _DEFAULT_ENV.items():
        os.environ.setdefault(key, value)
