"""Operational automation helpers for scheduled jobs."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from . import chaos, ledger, payments
from .alerting import EmailTransport, PagerDutyTransport, SlackTransport
from .config import get_settings
from .secret_manager import SecretUpdateError
from .secret_rotation import rotate_core_application_secrets
from .schema_lifecycle import SchemaLifecycleError, rehearse_schema
from .seeding import seed_environment, validate_environment
from .metrics import record_automation_job
from .tasks import requeue_failed_reminders

logger = logging.getLogger(__name__)

AlertHook = Callable[[str, dict[str, object]], None]
Verifier = Callable[[Path], dict[str, object]]
BackupLocator = Callable[[], Path | None]


@dataclass(slots=True, frozen=True)
class AlertChannel:
    """Represents an alerting destination for automation failures."""

    kind: str
    target: str
    severity: str = "critical"
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class AlertEvent:
    """Record emitted alert payloads for observability and testing."""

    event: str
    channel: AlertChannel
    payload: dict[str, object]
    emitted_at: datetime


@dataclass(slots=True)
class ScheduledJob:
    """Metadata describing a scheduled automation task."""

    name: str
    schedule: str
    description: str
    target: str | None = None
    alerts: tuple[AlertChannel, ...] = ()
    metrics: tuple[str, ...] = ()


@dataclass(slots=True)
class JobExecution:
    """Represents the outcome of executing an automation task."""

    name: str
    ran_at: datetime
    success: bool
    details: dict[str, object]


def _default_backup_locator(pattern: str) -> Path | None:
    candidates = sorted(
        (candidate for candidate in Path.cwd().glob(pattern) if candidate.is_file()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _default_backup_verifier(backup: Path) -> dict[str, object]:
    resolved_backup = backup.resolve(strict=True)
    workdir = Path.cwd().resolve()
    if not resolved_backup.is_relative_to(workdir):
        raise ValueError("Backup path must be within the working directory")

    payload: dict[str, object] = {
        "bytes": resolved_backup.stat().st_size,
        "sha256": _digest_file(resolved_backup),
    }

    try:
        _validate_backup(resolved_backup)
    except Exception as exc:
        payload["ok"] = False
        payload["error"] = str(exc)
    else:
        payload["ok"] = True

    return payload


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_backup(path: Path) -> None:
    suffix = path.suffix.lower()
    if suffix in {".db", ".sqlite"}:
        _validate_sqlite(path)
        return
    if suffix == ".sql":
        _validate_sql_dump(path)
        return
    raise ValueError(f"Unsupported backup format: {path.suffix}")


def _validate_sqlite(path: Path) -> None:
    uri = f"file:{path}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True) as connection:
            cursor = connection.execute("PRAGMA integrity_check;")
            result = cursor.fetchone()
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"SQLite integrity check failed: {exc}") from exc
    if not result or result[0] != "ok":
        raise ValueError(f"SQLite integrity check reported: {result[0] if result else 'unknown'}")


def _validate_sql_dump(path: Path) -> None:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        first_line = handle.readline().strip()
        if not first_line:
            raise ValueError("SQL dump appears to be empty")
        lowered = first_line.lower()
        if "postgresql database dump" in lowered:
            return
        if "mysql dump" in lowered:
            for line in handle:
                if line.strip().lower().startswith("create table"):
                    return
            raise ValueError("MySQL dump does not contain CREATE TABLE statements")
    # For other SQL dumps, require explicit acknowledgement
    raise ValueError("Unrecognized SQL dump format; expected PostgreSQL or MySQL header")


_ALERT_CHANNELS: list[AlertChannel] = []
_ALERT_EVENTS: list[AlertEvent] = []
_ALERT_BINDINGS: list[tuple[AlertChannel, Callable[[str, dict[str, object]], None]]] = (
    []
)


def _wrap_notifier(
    channel: AlertChannel, transport
) -> Callable[[str, dict[str, object]], None]:
    def _sender(event: str, payload: dict[str, object]) -> None:
        transport.notify(event=event, severity=channel.severity, payload=payload)

    return _sender


def _build_notifier(
    channel: AlertChannel,
) -> Callable[[str, dict[str, object]], None] | None:
    settings = get_settings()
    if channel.kind == "pagerduty":
        routing_key = (
            channel.metadata.get("routing_key")
            or getattr(settings, "automation_pagerduty_routing_key", None)
        )
        if not routing_key:
            logger.warning(
                "Skipping PagerDuty channel %s because no routing key was configured",
                channel.target,
            )
            return None
        return _wrap_notifier(channel, PagerDutyTransport(routing_key))
    if channel.kind == "slack":
        webhook = channel.metadata.get("webhook") or getattr(settings, "automation_slack_webhook", None)
        if not webhook:
            logger.warning(
                "Skipping Slack channel %s because no webhook URL was configured",
                channel.target,
            )
            return None
        return _wrap_notifier(channel, SlackTransport(webhook))
    if channel.kind == "email":
        recipients = channel.metadata.get("recipients") or channel.target
        recipient_list = [
            item.strip() for item in recipients.split(",") if item.strip()
        ]
        if not recipient_list:
            logger.warning(
                "Skipping email channel %s because no recipients were provided",
                channel.target,
            )
            return None
        return _wrap_notifier(
            channel, EmailTransport(settings=settings, recipients=recipient_list)
        )
    logger.warning("Unknown alert channel kind '%s'; skipping", channel.kind)
    return None


def _default_channels_from_settings() -> tuple[AlertChannel, ...]:
    settings = get_settings()
    channels: list[AlertChannel] = []
    pagerduty_routing_key = getattr(settings, "automation_pagerduty_routing_key", None)
    if settings.automation_pagerduty_service:
        channels.append(
            AlertChannel(
                kind="pagerduty",
                target=settings.automation_pagerduty_service,
                severity="critical",
                metadata={"routing_key": pagerduty_routing_key or ""},
            )
        )
    if settings.automation_slack_channel:
        slack_webhook = getattr(settings, "automation_slack_webhook", None)
        channels.append(
            AlertChannel(
                kind="slack",
                target=settings.automation_slack_channel,
                severity="warning",
                metadata={
                    "webhook": slack_webhook or "",
                    "channel": settings.automation_slack_channel,
                },
            )
        )
    email_recipients = getattr(settings, "automation_email_recipients", ())
    if email_recipients:
        recipient_list = ",".join(email_recipients)
        channels.append(
            AlertChannel(
                kind="email",
                target=recipient_list,
                severity="warning",
                metadata={"recipients": recipient_list},
            )
        )
    return tuple(channels)


def configure_alert_channels(channels: Iterable[AlertChannel]) -> None:
    """Replace the configured alert channels."""

    global _ALERT_BINDINGS
    _ALERT_CHANNELS.clear()
    _ALERT_CHANNELS.extend(channels)
    _ALERT_BINDINGS = []
    for channel in _ALERT_CHANNELS:
        notifier = _build_notifier(channel)
        if notifier is not None:
            _ALERT_BINDINGS.append((channel, notifier))


configure_alert_channels(_default_channels_from_settings())


def drain_alert_events() -> tuple[AlertEvent, ...]:
    """Return and clear pending alert events (primarily for tests)."""

    events = tuple(_ALERT_EVENTS)
    _ALERT_EVENTS.clear()
    return events


def _emit_alert(event: str, payload: dict[str, object]) -> None:
    timestamp = datetime.now(tz=UTC)
    for channel in _ALERT_CHANNELS:
        _ALERT_EVENTS.append(
            AlertEvent(
                event=event,
                channel=channel,
                payload=dict(payload),
                emitted_at=timestamp,
            )
        )
        logger.warning(
            "automation alert %s via %s (target=%s)",
            event,
            channel.kind,
            channel.target,
        )
    for channel, notifier in _ALERT_BINDINGS:
        try:
            notifier(event, payload)
        except Exception as exc:  # pragma: no cover - transport level failures
            logger.exception(
                "Failed delivering automation alert %s via %s: %s",
                event,
                channel.kind,
                exc,
            )


def dispatch_alert(event: str, payload: dict[str, object]) -> None:
    """Expose alert fan-out for other modules (incidents)."""

    _emit_alert(event, payload)


def run_dlq_reprocessor(
    *, alert: AlertHook | None = None, limit: int | None = None
) -> JobExecution:
    """Requeue failed reminder jobs and emit alerts on failures."""

    settings = get_settings()
    batch_size = limit or settings.dlq_reprocessor_batch_size
    summary = requeue_failed_reminders(limit=batch_size)
    success = summary.get("failed", 0) == 0
    alert_hook = alert or _emit_alert
    if not success:
        alert_hook("dlq_reprocessor_failure", summary)
    metrics_payload = {
        "failed": summary.get("failed", 0),
        "requeued": summary.get("requeued", 0),
        "selected": summary.get("selected", 0),
    }
    record_automation_job(
        "dlq_reprocessor",
        success=success,
        metrics=metrics_payload,
    )
    execution = JobExecution(
        name="dlq_reprocessor",
        ran_at=datetime.now(tz=UTC),
        success=success,
        details=summary,
    )
    ledger.record_automation_execution(
        job_name=execution.name,
        ran_at=execution.ran_at,
        success=execution.success,
        metrics=metrics_payload,
        details=summary,
        scheduler=settings.automation_scheduler_target,
        triggered_by="automation",
    )
    return execution


def run_backup_verification(
    *,
    alert: AlertHook | None = None,
    locator: BackupLocator | None = None,
    verifier: Verifier | None = None,
) -> JobExecution:
    """Verify the most recent backup and alert on anomalies."""

    settings = get_settings()
    locator = locator or (
        lambda: _default_backup_locator(settings.backup_verification_glob)
    )
    verifier = verifier or _default_backup_verifier

    backup_path = locator()
    alert_hook = alert or _emit_alert

    if backup_path is None:
        details = {"status": "missing", "pattern": settings.backup_verification_glob}
        alert_hook("backup_missing", details)
        metrics_payload = {"status": "missing"}
        record_automation_job(
            "backup_verification",
            success=False,
            metrics=metrics_payload,
        )
        execution = JobExecution(
            name="backup_verification",
            ran_at=datetime.now(tz=UTC),
            success=False,
            details=details,
        )
        ledger.record_automation_execution(
            job_name=execution.name,
            ran_at=execution.ran_at,
            success=False,
            metrics=metrics_payload,
            details=details,
            scheduler=settings.automation_scheduler_target,
            triggered_by="automation",
        )
        return execution

    try:
        result = verifier(backup_path)
    except Exception as exc:  # pragma: no cover - verifier implementation dependent
        details = {"status": "error", "path": str(backup_path), "error": str(exc)}
        alert_hook("backup_verification_error", details)
        metrics_payload = {"status": "error"}
        record_automation_job(
            "backup_verification",
            success=False,
            metrics=metrics_payload,
        )
        execution = JobExecution(
            name="backup_verification",
            ran_at=datetime.now(tz=UTC),
            success=False,
            details=details,
        )
        ledger.record_automation_execution(
            job_name=execution.name,
            ran_at=execution.ran_at,
            success=False,
            metrics=metrics_payload,
            details=details,
            scheduler=settings.automation_scheduler_target,
            triggered_by="automation",
        )
        return execution

    success = bool(result.get("ok"))
    if not success:
        alert_hook("backup_verification_failed", result)
    metrics_payload = {
        "bytes": result.get("bytes", 0),
        "ok": int(bool(result.get("ok"))),
    }
    record_automation_job(
        "backup_verification",
        success=success,
        metrics=metrics_payload,
    )
    details_payload = result | {"path": str(backup_path)}
    execution = JobExecution(
        name="backup_verification",
        ran_at=datetime.now(tz=UTC),
        success=success,
        details=details_payload,
    )
    ledger.record_automation_execution(
        job_name=execution.name,
        ran_at=execution.ran_at,
        success=success,
        metrics=metrics_payload,
        details=details_payload,
        scheduler=settings.automation_scheduler_target,
        triggered_by="automation",
    )
    return execution


def run_schema_rehearsal(
    *,
    downgrade_target: str | None = None,
    alert: AlertHook | None = None,
) -> JobExecution:
    """Execute a downgrade/upgrade rehearsal and reseed the environment."""

    settings = get_settings()
    target = downgrade_target or settings.schema_rehearsal_downgrade_target
    alert_hook = alert or _emit_alert

    metrics_payload = {"target": target, "downgrade_completed": 0}

    try:
        result = rehearse_schema(
            downgrade_target=target, apply_seeds=True, reset_seeds=True
        )
        details = result.as_dict()
        success = True
        metrics_payload["downgrade_completed"] = int(result.downgrade_completed)
        if result.snapshot_checksum:
            metrics_payload["snapshot_checksum"] = result.snapshot_checksum
    except SchemaLifecycleError as exc:
        success = False
        details = {
            "error": str(exc),
            "action": exc.action,
            "target": exc.target,
        }
        alert_hook("schema_rehearsal_failure", details)

    record_automation_job(
        "schema_rehearsal",
        success=success,
        metrics=metrics_payload,
    )

    execution = JobExecution(
        name="schema_rehearsal",
        ran_at=datetime.now(tz=UTC),
        success=success,
        details=details,
    )

    ledger.record_automation_execution(
        job_name=execution.name,
        ran_at=execution.ran_at,
        success=success,
        metrics=metrics_payload,
        details=details,
        scheduler=settings.automation_scheduler_target,
        triggered_by="automation",
    )
    return execution


def run_environment_seed(
    *,
    dataset_path: str | None = None,
    alert: AlertHook | None = None,
) -> JobExecution:
    """Seed the environment using the canonical dataset and validate it."""

    alert_hook = alert or _emit_alert
    settings = get_settings()
    dataset: dict[str, object] | None = None

    source_path = dataset_path or settings.environment_seed_dataset

    if source_path:
        candidate = Path(source_path)
        if not candidate.exists():
            details = {"error": "dataset_not_found", "path": str(candidate)}
            alert_hook("environment_seed_missing_dataset", details)
            return JobExecution(
                name="environment_seed",
                ran_at=datetime.now(tz=UTC),
                success=False,
                details=details,
            )
        dataset = json.loads(candidate.read_text())

    seed_summary = seed_environment(dataset, reset=True, apply_backfill=True)
    validation = validate_environment(dataset)

    success = validation.get("score", 0.0) >= 1.0
    details = {
        "seed_summary": seed_summary.as_dict(),
        "validation": validation,
    }

    if not success:
        alert_hook("environment_seed_validation_failed", details)

    record_automation_job(
        "environment_seed",
        success=success,
        metrics={"score": validation.get("score", 0.0)},
    )

    execution = JobExecution(
        name="environment_seed",
        ran_at=datetime.now(tz=UTC),
        success=success,
        details=details,
    )

    ledger.record_automation_execution(
        job_name=execution.name,
        ran_at=execution.ran_at,
        success=success,
        metrics={"score": validation.get("score", 0.0)},
        details=details,
        scheduler=get_settings().automation_scheduler_target,
        triggered_by="automation",
    )
    return execution


def run_chaos_game_day(*, alert: AlertHook | None = None) -> JobExecution:
    """Execute scheduled chaos experiments covering upstream degradations."""

    alert_hook = alert or _emit_alert

    experiments = chaos.build_dependency_game_day()
    results = chaos.run_experiments(experiments)
    success = all(result.succeeded for result in results)

    if not success:
        alert_hook(
            "chaos_game_day_failure",
            {
                "results": [result.__dict__ for result in results],
            },
        )

    metrics_payload = {
        "experiments": len(results),
        "failures": sum(0 if result.succeeded else 1 for result in results),
    }
    record_automation_job(
        "chaos_game_day",
        success=success,
        metrics=metrics_payload,
    )

    execution = JobExecution(
        name="chaos_game_day",
        ran_at=datetime.now(tz=UTC),
        success=success,
        details={
            "results": [result.__dict__ for result in results],
        },
    )

    ledger.record_automation_execution(
        job_name=execution.name,
        ran_at=execution.ran_at,
        success=success,
        metrics=metrics_payload,
        details=execution.details,
        scheduler=get_settings().automation_scheduler_target,
        triggered_by="automation",
    )
    return execution


def run_webhook_secret_rotation(
    *,
    alert: AlertHook | None = None,
    generator: Callable[[], str] | None = None,
    now: datetime | None = None,
) -> JobExecution:
    """Rotate Stripe webhook secrets when due and retire expired ones."""

    alert_hook = alert or _emit_alert
    generator = generator or (lambda: secrets.token_urlsafe(48))
    moment = now or datetime.now(tz=UTC)

    retired = payments.purge_expired_webhook_secrets(now=moment)
    due_at = payments.next_webhook_rotation(now=moment)

    metrics = {"rotated": 0, "retired": retired}
    details: dict[str, object] = {
        "due_at": due_at.isoformat(),
        "retired": retired,
        "rotated": False,
    }

    if moment < due_at:
        record_automation_job("webhook_secret_rotation", success=True, metrics=metrics)
        execution = JobExecution(
            name="webhook_secret_rotation",
            ran_at=moment,
            success=True,
            details=details,
        )
        ledger.record_automation_execution(
            job_name=execution.name,
            ran_at=execution.ran_at,
            success=True,
            metrics=metrics,
            details=details,
            scheduler=get_settings().automation_scheduler_target,
            triggered_by="automation",
        )
        return execution

    try:
        state = payments.rotate_webhook_secret(generator)
    except Exception as exc:  # pragma: no cover - generator implementation dependent
        error = {"error": str(exc)}
        details.update(error)
        alert_hook("webhook_rotation_failed", details)
        record_automation_job("webhook_secret_rotation", success=False, metrics=metrics)
        execution = JobExecution(
            name="webhook_secret_rotation",
            ran_at=moment,
            success=False,
            details=details,
        )
        ledger.record_automation_execution(
            job_name=execution.name,
            ran_at=execution.ran_at,
            success=False,
            metrics=metrics,
            details=details,
            scheduler=get_settings().automation_scheduler_target,
            triggered_by="automation",
        )
        return execution

    metrics["rotated"] = 1
    details.update(
        {
            "rotated": True,
            "activates_at": state.activates_at.isoformat(),
            "retires_at": state.retires_at.isoformat() if state.retires_at else None,
            "next_rotation": payments.next_webhook_rotation(
                now=state.activates_at
            ).isoformat(),
        }
    )

    record_automation_job("webhook_secret_rotation", success=True, metrics=metrics)
    execution = JobExecution(
        name="webhook_secret_rotation",
        ran_at=moment,
        success=True,
        details=details,
    )
    ledger.record_automation_execution(
        job_name=execution.name,
        ran_at=execution.ran_at,
        success=True,
        metrics=metrics,
        details=details,
        scheduler=get_settings().automation_scheduler_target,
        triggered_by="automation",
    )
    return execution


def run_core_secret_rotation(
    *, alert: AlertHook | None = None, generator: Callable[[], str] | None = None
) -> JobExecution:
    """Rotate core application secrets sourced from managed providers."""

    settings = get_settings()
    alert_hook = alert or _emit_alert
    metrics = {"rotated": 0}

    try:
        results = rotate_core_application_secrets(settings, generator=generator)
    except SecretUpdateError as exc:
        details = {"status": "failure", "error": str(exc)}
        alert_hook("core_secret_rotation_failed", details)
        record_automation_job("core_secret_rotation", success=False, metrics=metrics)
        execution = JobExecution(
            name="core_secret_rotation",
            ran_at=datetime.now(tz=UTC),
            success=False,
            details=details,
        )
        ledger.record_automation_execution(
            job_name=execution.name,
            ran_at=execution.ran_at,
            success=False,
            metrics=metrics,
            details=details,
            scheduler=settings.automation_scheduler_target,
            triggered_by="automation",
        )
        return execution

    metrics["rotated"] = len(results)
    details = {
        "status": "success",
        "rotated": [
            {
                "name": result.name,
                "reference": result.reference,
                "metadata": result.managed_secret.metadata,
            }
            for result in results
        ],
    }
    record_automation_job("core_secret_rotation", success=True, metrics=metrics)
    execution = JobExecution(
        name="core_secret_rotation",
        ran_at=datetime.now(tz=UTC),
        success=True,
        details=details,
    )
    ledger.record_automation_execution(
        job_name=execution.name,
        ran_at=execution.ran_at,
        success=True,
        metrics=metrics,
        details=details,
        scheduler=settings.automation_scheduler_target,
        triggered_by="automation",
    )
    return execution


def scheduled_jobs() -> Sequence[ScheduledJob]:
    """Return the cron-style schedules for the automation tasks."""

    settings = get_settings()
    target = settings.automation_scheduler_target
    secret_rotation_schedule = getattr(
        settings,
        "secret_rotation_schedule",
        getattr(settings, "webhook_secret_rotation_schedule", "0 0 * * *"),
    )
    return (
        ScheduledJob(
            name="dlq_reprocessor",
            schedule=settings.dlq_reprocessor_schedule,
            description="Requeue reminder DLQ jobs and notify on failures",
            target=target,
            alerts=tuple(_ALERT_CHANNELS),
            metrics=("failed", "requeued", "selected"),
        ),
        ScheduledJob(
            name="backup_verification",
            schedule=settings.backup_verification_schedule,
            description="Validate the most recent database backup",
            target=target,
            alerts=tuple(_ALERT_CHANNELS),
            metrics=("ok", "bytes"),
        ),
        ScheduledJob(
            name="webhook_secret_rotation",
            schedule=settings.webhook_secret_rotation_schedule,
            description="Rotate Stripe webhook signing secrets",
            target=target,
            alerts=tuple(_ALERT_CHANNELS),
            metrics=("rotated", "retired"),
        ),
        ScheduledJob(
            name="core_secret_rotation",
            schedule=secret_rotation_schedule,
            description="Rotate core application secrets stored in managed providers",
            target=target,
            alerts=tuple(_ALERT_CHANNELS),
            metrics=("rotated",),
        ),
        ScheduledJob(
            name="schema_rehearsal",
            schedule=settings.schema_rehearsal_schedule,
            description="Rehearse downgrade/backfill automation and reseed datasets",
            target=target,
            alerts=tuple(_ALERT_CHANNELS),
            metrics=("target",),
        ),
        ScheduledJob(
            name="chaos_game_day",
            schedule=settings.chaos_game_day_schedule,
            description="Run dependency degradation chaos experiments",
            target=target,
            alerts=tuple(_ALERT_CHANNELS),
            metrics=("experiments", "failures"),
        ),
    )


def managed_schedule_payload() -> tuple[dict[str, object], ...]:
    """Return a serializable representation of the managed schedules."""

    schedules: list[dict[str, object]] = []
    for job in scheduled_jobs():
        schedules.append(
            {
                "name": job.name,
                "schedule": job.schedule,
                "description": job.description,
                "target": job.target,
                "alerts": [
                    {
                        "kind": channel.kind,
                        "target": channel.target,
                        "severity": channel.severity,
                        "metadata": dict(channel.metadata),
                    }
                    for channel in job.alerts
                ],
                "metrics": list(job.metrics),
            }
        )
    return tuple(schedules)


__all__ = [
    "AlertChannel",
    "AlertEvent",
    "AlertHook",
    "BackupLocator",
    "JobExecution",
    "ScheduledJob",
    "Verifier",
    "configure_alert_channels",
    "drain_alert_events",
    "managed_schedule_payload",
    "run_backup_verification",
    "run_chaos_game_day",
    "run_dlq_reprocessor",
    "run_environment_seed",
    "run_schema_rehearsal",
    "run_webhook_secret_rotation",
    "run_core_secret_rotation",
    "scheduled_jobs",
    "dispatch_alert",
]
