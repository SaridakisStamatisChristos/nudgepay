from pathlib import Path
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app import automation


@pytest.fixture(autouse=True)
def configure_settings(monkeypatch):
    settings = SimpleNamespace(
        dlq_reprocessor_batch_size=100,
        backup_verification_glob="backups/*",
        dlq_reprocessor_schedule="*/5 * * * *",
        backup_verification_schedule="0 2 * * *",
        webhook_secret_rotation_schedule="15 1 * * *",
        automation_pagerduty_service="pd/service",
        automation_slack_channel="#alerts",
        automation_scheduler_target="github-actions",
        schema_rehearsal_schedule="0 4 * * 0",
        schema_rehearsal_downgrade_target="base",
        chaos_game_day_schedule="0 3 * * 1",
        environment_seed_dataset=None,
    )
    monkeypatch.setattr(automation, "get_settings", lambda: settings)
    automation.configure_alert_channels(automation._default_channels_from_settings())
    automation.drain_alert_events()
    return settings


def test_run_dlq_reprocessor_records_metrics(monkeypatch):
    monkeypatch.setattr(
        automation,
        "requeue_failed_reminders",
        lambda limit: {"selected": 3, "requeued": 2, "failed": 1},
    )

    result = automation.run_dlq_reprocessor()

    assert not result.success
    events = automation.drain_alert_events()
    assert len(events) == 2
    kinds = {event.channel.kind for event in events}
    assert events[0].event == "dlq_reprocessor_failure"
    assert kinds == {"pagerduty", "slack"}


def test_run_backup_verification_handles_missing_backup(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(automation, "_default_backup_locator", lambda pattern: None)

    result = automation.run_backup_verification()

    assert result.success is False
    events = automation.drain_alert_events()
    assert events and events[0].event == "backup_missing"


def test_run_backup_verification_invokes_verifier(monkeypatch, tmp_path: Path):
    backup = tmp_path / "backup.db"
    backup.write_text("dummy")

    def fake_locator():
        return backup

    def fake_verifier(path: Path):
        assert path == backup
        return {"ok": True, "bytes": 1024}

    result = automation.run_backup_verification(
        locator=fake_locator, verifier=fake_verifier
    )

    assert result.success
    assert automation.drain_alert_events() == ()


def test_managed_schedule_payload_exposes_alerts():
    schedules = automation.managed_schedule_payload()
    assert schedules
    assert schedules[0]["alerts"]
    assert any(job["name"] == "webhook_secret_rotation" for job in schedules)
    assert schedules[0]["target"] == "github-actions"


def test_run_webhook_rotation_skips_when_not_due(monkeypatch):
    now = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)

    monkeypatch.setattr(
        automation.payments,
        "purge_expired_webhook_secrets",
        lambda now=None: 0,
    )
    monkeypatch.setattr(
        automation.payments,
        "next_webhook_rotation",
        lambda now=None: now + timedelta(days=1),
    )

    result = automation.run_webhook_secret_rotation(now=now)

    assert result.success
    assert result.details["rotated"] is False
    assert automation.drain_alert_events() == ()


def test_run_webhook_rotation_rotates_and_records(monkeypatch):
    now = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
    state = SimpleNamespace(
        activates_at=now,
        retires_at=now + timedelta(seconds=3600),
    )

    rotation_calls: list[str] = []
    rotation_window = {"first": True}

    def fake_rotate(generator):
        rotation_calls.append(generator())
        return state

    def fake_next_rotation(*, now: datetime | None = None):
        if rotation_window["first"]:
            rotation_window["first"] = False
            assert now == moment_anchor
            return moment_anchor - timedelta(minutes=5)
        assert now == state.activates_at
        return state.activates_at + timedelta(days=7)

    moment_anchor = now
    monkeypatch.setattr(automation.payments, "rotate_webhook_secret", fake_rotate)
    monkeypatch.setattr(
        automation.payments, "purge_expired_webhook_secrets", lambda now=None: 2
    )
    monkeypatch.setattr(
        automation.payments, "next_webhook_rotation", fake_next_rotation
    )

    result = automation.run_webhook_secret_rotation(generator=lambda: "secret", now=now)

    assert result.success
    assert result.details["rotated"] is True
    assert result.details["retired"] == 2
    assert rotation_calls == ["secret"]
    assert "next_rotation" in result.details
    assert automation.drain_alert_events() == ()
