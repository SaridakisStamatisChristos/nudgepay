import json
from datetime import datetime, timedelta, timezone

from sqlmodel import delete, select

from app.tasks import reminder_dashboard_snapshot, requeue_dead_letter_jobs
from app.db import init_db, session_scope
from app.models import OutboundJob


def _reset_jobs() -> None:
    init_db()
    with session_scope() as session:
        session.exec(delete(OutboundJob))
        session.commit()


def test_reminder_dashboard_snapshot(monkeypatch):
    _reset_jobs()
    now = datetime.now(tz=timezone.utc)
    with session_scope() as session:
        session.add(
            OutboundJob(
                job_key="reminder:1",
                job_type="reminder",
                payload=json.dumps({"invoice_id": 1, "stage": "DUE", "base_url": "http://test"}),
                status="queued",
                created_at=now,
            )
        )
        session.add(
            OutboundJob(
                job_key="reminder:2",
                job_type="reminder",
                payload=json.dumps({"invoice_id": 2, "stage": "DUE", "base_url": "http://test"}),
                status="failed",
                updated_at=now - timedelta(hours=2),
            )
        )
        session.add(
            OutboundJob(
                job_key="reminder:3",
                job_type="reminder",
                payload=json.dumps({"invoice_id": 3, "stage": "DUE", "base_url": "http://test"}),
                status="succeeded",
                completed_at=now - timedelta(hours=1),
            )
        )
        session.commit()

    snapshot = reminder_dashboard_snapshot(now=now)
    assert snapshot.queued == 1
    assert snapshot.failed == 1
    assert snapshot.retryable == 1
    assert snapshot.succeeded_last_24h >= 1
    assert snapshot.oldest_failure_age_seconds >= 7200


def test_requeue_dead_letter_jobs(monkeypatch):
    _reset_jobs()
    payload = {"invoice_id": 10, "stage": "DUE", "base_url": "http://test"}
    with session_scope() as session:
        session.add(
            OutboundJob(
                job_key="reminder:dead",
                job_type="reminder",
                payload=json.dumps(payload),
                status="failed",
            )
        )
        session.commit()

    calls = []

    def fake_enqueue(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(
        "app.tasks.enqueue_reminder",
        lambda invoice_id, stage, base_url, force_inline=False: fake_enqueue(
            invoice_id=invoice_id,
            stage=stage,
            base_url=base_url,
        ),
    )

    requeued = requeue_dead_letter_jobs(limit=5)
    assert requeued == 1
    assert calls[0] == payload
    with session_scope() as session:
        job = session.exec(
            select(OutboundJob).where(OutboundJob.job_key == "reminder:dead")
        ).one()
        assert job.status == "queued"
