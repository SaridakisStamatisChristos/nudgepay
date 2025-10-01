"""Background job helpers backed by Redis and RQ."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional, Sequence

try:  # pragma: no cover - optional dependency
    from redis.exceptions import RedisError
except ImportError:  # pragma: no cover - optional dependency
    class RedisError(Exception):
        pass

try:  # pragma: no cover - optional dependency
    from rq import Queue
    from rq.job import Job
    from rq.retry import Retry
except ImportError:  # pragma: no cover - optional dependency
    Queue = None
    Job = None
    Retry = None

from sqlalchemy import func
from sqlmodel import select

from .config import get_settings
from .db import session_scope
from . import emailer
from .metrics import record_reminder
from .models import Client, Invoice, OutboundJob, ReminderLog, utcnow
from .redis_utils import get_redis

logger = logging.getLogger(__name__)
settings = get_settings()

_redis = get_redis()
if _redis is not None and Queue is not None:
    _queue = Queue(settings.task_queue_name, connection=_redis, default_timeout=600)
else:  # pragma: no cover - optional dependency
    _queue = None


def _job_key(prefix: str, payload: Dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True)
    return f"{prefix}:{serialized}"


def enqueue_secret_invalidation(
    spec: str,
    metadata: Dict[str, Any] | None = None,
    *,
    stage: str = "default",
    warm_up_seconds: int = 0,
    queues: Sequence[str] | None = None,
) -> Job | None:
    """Fan out secret rotation to workers via the task queue."""

    metadata = metadata or {}
    queues = tuple(queue for queue in (queues or ()) if queue)
    payload: Dict[str, Any] = {
        "spec": spec,
        "metadata": metadata,
        "stage": stage,
        "queues": list(queues),
        "warm_up_seconds": warm_up_seconds,
    }
    job_key = _job_key("secret-invalidation", payload)

    schedule_at: datetime | None = None
    if warm_up_seconds > 0:
        schedule_at = datetime.now(tz=UTC) + timedelta(seconds=warm_up_seconds)

    if _queue is None:
        logger.info("Queue unavailable; running secret invalidation inline for %s", spec)
        process_secret_invalidation(spec=spec, metadata=metadata, stage=stage, queues=queues)
        return None

    kwargs = {"spec": spec, "metadata": metadata, "stage": stage, "queues": list(queues)}
    meta = {"stage": stage, "queues": list(queues), "warm_up_seconds": warm_up_seconds}
    try:
        if schedule_at and hasattr(_queue, "enqueue_at"):
            job = _queue.enqueue_at(  # type: ignore[attr-defined]
                schedule_at,
                "nudgepay.app.tasks.process_secret_invalidation",
                kwargs=kwargs,
                job_id=job_key,
                retry=Retry(max=3, interval=[10, 30, 90]),
                result_ttl=3600,
                meta=meta,
            )
        else:
            if schedule_at:
                meta["not_before"] = schedule_at.isoformat()
            job = _queue.enqueue_call(
                "nudgepay.app.tasks.process_secret_invalidation",
                kwargs=kwargs,
                job_id=job_key,
                retry=Retry(max=3, interval=[10, 30, 90]),
                result_ttl=3600,
                meta=meta,
            )
        logger.info(
            "Queued secret invalidation for %s (stage=%s, delay=%s)",
            spec,
            stage,
            warm_up_seconds,
        )
        return job
    except RedisError:
        logger.warning("Redis unavailable for secret invalidation of %s; running inline", spec, exc_info=True)
        process_secret_invalidation(spec=spec, metadata=metadata, stage=stage, queues=queues)
        return None


def process_secret_invalidation(
    *, spec: str, metadata: Dict[str, Any] | None = None, stage: str = "default", queues: Sequence[str] | None = None
) -> None:
    """Execute cache invalidation on workers after rotation."""

    from . import cache_invalidation  # local import to avoid cycles

    payload = dict(metadata or {})
    payload["stage"] = stage
    payload["queues"] = list(queues or [])
    cache_invalidation.notify_secret_rotation(spec, payload)


def enqueue_reminder(
    invoice_id: int,
    stage: str,
    base_url: str,
    *,
    force_inline: bool = False,
    to: Optional[str] = None,
) -> Job | None:
    payload = {"invoice_id": invoice_id, "stage": stage, "base_url": base_url}
    if to:
        payload["to"] = to
    job_key = _job_key("reminder", payload)

    with session_scope() as session:
        existing = session.exec(
            select(OutboundJob).where(OutboundJob.job_key == job_key)
        ).first()
        if existing and existing.status == "succeeded" and stage != "manual":
            logger.info("Skipping duplicate reminder job %s", job_key)
            try:
                return Job.fetch(job_key, connection=_redis)
            except Exception:  # pragma: no cover - queue state dependent
                logger.debug("Job %s missing from queue; enqueuing again", job_key)

        if not existing:
            existing = OutboundJob(job_key=job_key, job_type="reminder", payload=json.dumps(payload))
        existing.status = "queued"
        existing.attempts += 1
        existing.updated_at = utcnow()
        session.add(existing)

    inline = force_inline or _queue is None
    if inline:
        if _queue is None:
            logger.warning(
                "Queue backend unavailable; running reminder inline for %s", job_key
            )
        else:
            logger.info(
                "Processing reminder inline for %s despite queue availability", job_key
            )
        process_reminder(**payload)
        return None

    try:
        job = _queue.enqueue_call(
            "nudgepay.app.tasks.process_reminder",
            kwargs=payload,
            job_id=job_key,
            retry=Retry(max=3, interval=[10, 30, 90]),
            result_ttl=86400,
        )
        logger.info("Queued reminder job %s", job.id)
        return job
    except RedisError:
        logger.warning("Redis unavailable for reminder job %s; running inline", job_key, exc_info=True)
        process_reminder(**payload)
        return None


def process_reminder(*, invoice_id: int, stage: str, base_url: str, to: Optional[str] = None) -> None:
    """Send a reminder email for ``invoice_id``."""

    with session_scope() as session:
        job_key = _job_key("reminder", {"invoice_id": invoice_id, "stage": stage, "base_url": base_url})
        job_record = session.exec(
            select(OutboundJob).where(OutboundJob.job_key == job_key)
        ).first()
        invoice = session.get(Invoice, invoice_id)
        if not invoice:
            if job_record:
                job_record.status = "skipped"
                job_record.last_error = "Invoice missing"
                session.add(job_record)
            return

        pay_url = invoice.stripe_payment_link or f"{base_url}/pay/{invoice.id}"
        client = session.get(Client, invoice.client_id)
        recipient = to or (client.email if client and client.email else None)
        if not recipient:
            details = "Client email missing"
            if job_record:
                job_record.status = "failed"
                job_record.last_error = details
                job_record.updated_at = utcnow()
                session.add(job_record)
            session.add(
                ReminderLog(invoice_id=invoice.id, kind=stage, result="failed", details=details)
            )
            record_reminder(stage, "failed")
            logger.warning(
                "Reminder job %s cannot send without a recipient", job_key
            )
            return
        subject = f"Quick nudge on Invoice {invoice.number}"
        amount = f"{invoice.amount_cents/100:.2f} {invoice.currency.upper()}"
        html = (
            f"<p>Hi, this is a friendly reminder for invoice <b>{invoice.number}</b> due on {invoice.due_date}.</p>"
            f"<p>Amount: <b>{amount}</b></p>"
            f"<p><a href=\"{pay_url}\">Pay securely here</a></p>"
        )

        # Update stored payload so downstream inspection sees the final recipient.
        if job_record:
            try:
                payload_data = json.loads(job_record.payload or "{}")
            except Exception:
                payload_data = {}
            if recipient:
                payload_data["to"] = recipient
                job_record.payload = json.dumps(payload_data)
                session.add(job_record)

        try:
            emailer.send_email(recipient, subject, html)
        except Exception as exc:  # pragma: no cover - network interactions
            if job_record:
                job_record.status = "failed"
                job_record.last_error = str(exc)
                job_record.updated_at = utcnow()
                session.add(job_record)
            session.add(
                ReminderLog(invoice_id=invoice.id, kind=stage, result="failed", details=str(exc))
            )
            record_reminder(stage, "failed")
            logger.exception("Reminder job %s failed", job_key)
            raise
        else:
            session.add(
                ReminderLog(invoice_id=invoice.id, kind=stage, result="sent")
            )
            record_reminder(stage, "sent")
            if job_record:
                job_record.status = "succeeded"
                job_record.completed_at = utcnow()
                job_record.updated_at = utcnow()
                session.add(job_record)
            logger.info("Reminder job %s completed", job_key)


@dataclass(frozen=True)
class ReminderDashboardSnapshot:
    queued: int
    failed: int
    retryable: int
    succeeded_last_24h: int
    oldest_failure_age_seconds: int | None


def reminder_dashboard_snapshot(now: datetime | None = None) -> ReminderDashboardSnapshot:
    """Return aggregate reminder job health suitable for dashboards."""

    now = now or utcnow()
    with session_scope() as session:
        summary = session.exec(
            select(OutboundJob.status, func.count())
            .where(OutboundJob.job_type == "reminder")
            .group_by(OutboundJob.status)
        ).all()
        counts = {status: count for status, count in summary}
        queued = int(counts.get("queued", 0))
        failed = int(counts.get("failed", 0))
        retryable = failed + int(counts.get("skipped", 0))
        oldest_failure = session.exec(
            select(OutboundJob.updated_at)
            .where(OutboundJob.job_type == "reminder")
            .where(OutboundJob.status == "failed")
            .order_by(OutboundJob.updated_at.asc())
            .limit(1)
        ).first()
        if oldest_failure:
            failure_ts = oldest_failure
            if failure_ts.tzinfo is None:
                failure_ts = failure_ts.replace(tzinfo=timezone.utc)
            oldest_age = int((now - failure_ts).total_seconds())
        else:
            oldest_age = None
        since = now - timedelta(hours=24)
        succeeded_last_24h = session.exec(
            select(func.count())
            .where(OutboundJob.job_type == "reminder")
            .where(OutboundJob.status == "succeeded")
            .where(OutboundJob.completed_at >= since)
        ).one()

    return ReminderDashboardSnapshot(
        queued=queued,
        failed=failed,
        retryable=retryable,
        succeeded_last_24h=int(succeeded_last_24h or 0),
        oldest_failure_age_seconds=oldest_age,
    )


def requeue_failed_reminders(
    limit: int = 100,
    *,
    requeue_fn: Callable[[int, str, str], object] | None = None,
) -> Dict[str, int]:
    """Re-enqueue failed reminder jobs from the durable outbox."""

    worker = requeue_fn or (
        lambda invoice_id, stage, base_url: enqueue_reminder(invoice_id, stage, base_url)
    )

    with session_scope() as session:
        records = session.exec(
            select(OutboundJob)
            .where(OutboundJob.job_type == "reminder")
            .where(OutboundJob.status.in_({"failed", "skipped"}))
            .order_by(OutboundJob.updated_at.asc())
            .limit(limit)
        ).all()
        candidates = [
            {
                "id": job.id,
                "job_key": job.job_key,
                "payload": job.payload,
            }
            for job in records
        ]

    processed = 0
    failures = 0
    for job in candidates:
        try:
            payload = json.loads(job["payload"])
        except json.JSONDecodeError as exc:
            logger.error("Invalid payload on outbound job %s: %s", job["job_key"], exc)
            failures += 1
            continue

        try:
            worker(
                int(payload["invoice_id"]),
                str(payload["stage"]),
                str(payload["base_url"]),
            )
            processed += 1
        except Exception as exc:  # pragma: no cover - depends on queue backend
            failures += 1
            logger.exception("Failed to requeue reminder job %s", job["job_key"])
            with session_scope() as session:
                record = session.get(OutboundJob, job["id"])
                if record:
                    record.last_error = str(exc)
                    record.updated_at = utcnow()
                    record.status = "failed"
                    session.add(record)

    logger.info(
        "Reprocessed %s reminder jobs from DLQ (%s failures)",
        processed,
        failures,
    )
    return {"selected": len(candidates), "requeued": processed, "failed": failures}


def requeue_dead_letter_jobs(job_type: str = "reminder", *, limit: int = 50) -> int:
    """Re-enqueue failed jobs for another attempt.

    Returns the number of jobs that were requeued.
    """

    payloads: list[Dict[str, Any]] = []
    with session_scope() as session:
        jobs = (
            session.exec(
                select(OutboundJob)
                .where(OutboundJob.job_type == job_type)
                .where(OutboundJob.status.in_({"failed", "skipped"}))
                .order_by(OutboundJob.updated_at.asc())
                .limit(limit)
            ).all()
        )
        for job in jobs:
            try:
                payload = json.loads(job.payload)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed payload for job %s", job.job_key)
                continue
            job.last_error = None
            job.status = "queued"
            job.updated_at = utcnow()
            session.add(job)
            payloads.append(payload)

    requeued = 0
    for payload in payloads:
        try:
            if job_type == "reminder":
                enqueue_reminder(**payload)
            else:
                logger.info("No dispatcher configured for job type %s", job_type)
            requeued += 1
        except Exception:  # pragma: no cover - dependent on queue availability
            logger.exception("Failed to requeue reminder payload %s", payload)
    return requeued


__all__ = [
    "ReminderDashboardSnapshot",
    "enqueue_reminder",
    "enqueue_secret_invalidation",
    "process_reminder",
    "process_secret_invalidation",
    "reminder_dashboard_snapshot",
    "requeue_dead_letter_jobs",
    "requeue_failed_reminders",
]
