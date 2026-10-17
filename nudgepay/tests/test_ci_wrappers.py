from __future__ import annotations

import json
import os
from typing import Any, Dict

import pytest
from sqlalchemy.exc import OperationalError

from nudgepay.scripts import ci_env, ci_schema_rehearsal, ci_validate_release
from app.schema_lifecycle import SchemaLifecycleError


_CI_KEYS = [
        "BASE_URL",
        "SESSION_SECRET",
        "SESSION_SECRET_REF",
        "SESSION_SECRET_VALUE",
        "CRON_SECRET",
        "CRON_SECRET_REF",
        "CRON_SECRET_VALUE",
        "CRON_HMAC_SECRET",
        "CRON_HMAC_SECRET_REF",
        "CRON_HMAC_SECRET_VALUE",
        "SERVICE_TOKEN_PEPPER",
        "SERVICE_TOKEN_PEPPER_REF",
        "SERVICE_TOKEN_PEPPER_VALUE",
        "ADMIN_PASSWORD_HASH",
        "ADMIN_PASSWORD_HASH_REF",
        "ADMIN_PASSWORD_HASH_VALUE",
        "ADMIN_TOTP_SECRET",
        "ADMIN_TOTP_SECRET_REF",
        "ADMIN_TOTP_SECRET_VALUE",
        "CSRF_SECRET",
        "CSRF_SECRET_VALUE",
        "STRIPE_SECRET_KEY",
        "STRIPE_SECRET_KEY_REF",
        "STRIPE_SECRET_KEY_VALUE",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_WEBHOOK_SECRET_REF",
        "STRIPE_WEBHOOK_SECRET_VALUE",
        "DATABASE_URL",
        "SESSION_HTTPS_ONLY",
        "AUTOMATION_PAGERDUTY_ROUTING_KEY",
        "AUTOMATION_PAGERDUTY_ROUTING_KEY_REF",
        "AUTOMATION_PAGERDUTY_ROUTING_KEY_VALUE",
        "AUTOMATION_SLACK_WEBHOOK",
        "AUTOMATION_SLACK_WEBHOOK_REF",
        "AUTOMATION_SLACK_WEBHOOK_VALUE",
]


@pytest.fixture(autouse=True)
def _clear_ci_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    previous = {key: os.environ.get(key) for key in _CI_KEYS}
    for key in _CI_KEYS:
        monkeypatch.delenv(key, raising=False)
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def test_apply_ci_environment_defaults_sets_missing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    ci_env.apply_ci_environment_defaults()
    assert os.environ["SESSION_SECRET"].startswith("env://")
    assert os.environ["SESSION_SECRET_VALUE"].startswith("ci-session-secret-value")
    assert os.environ["BASE_URL"].startswith("https://")


def test_apply_ci_environment_defaults_does_not_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASE_URL", "https://custom.example")
    ci_env.apply_ci_environment_defaults()
    assert os.environ["BASE_URL"] == "https://custom.example"


def test_ci_validate_release_uses_defaults(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("ENVIRONMENT", "staging")
    exit_code = ci_validate_release.main()
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["environment"] == "staging"
    assert payload["errors"] == []


def test_ci_schema_rehearsal_skips_when_db_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "staging")
    error = OperationalError("select 1", {}, Exception("connection refused"))
    monkeypatch.setattr(
        ci_schema_rehearsal, "rehearse_schema", lambda **_: (_ for _ in ()).throw(SchemaLifecycleError("upgrade", "head", error)))

    exit_code = ci_schema_rehearsal.main(["--json"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["skipped"] is True


def test_ci_schema_rehearsal_success_path(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("ENVIRONMENT", "staging")

    class DummyResult:
        def as_dict(self) -> Dict[str, Any]:
            return {
                "start_revision": "abc",
                "end_revision": "def",
                "downgrade_target": "base",
                "steps": [
                    {"action": "downgrade", "target": "base", "success": True, "error": None}
                ],
                "seed_summary": None,
                "snapshot_checksum": None,
                "snapshot_counts": {},
                "downgrade_completed": True,
            }

    monkeypatch.setattr(ci_schema_rehearsal, "rehearse_schema", lambda **_: DummyResult())

    exit_code = ci_schema_rehearsal.main(["--json"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["end_revision"] == "def"
