import json
from datetime import datetime, timezone

from sqlmodel import delete

from app.db import init_db, session_scope
from app.models import OutboundJob
from app.tasks import requeue_failed_reminders


def test_requeue_failed_reminders(monkeypatch):
    init_db()
    with session_scope() as session:
        session.exec(delete(OutboundJob))
        session.commit()

        job1 = OutboundJob(
            job_key="reminder:{\"invoice_id\":1,\"stage\":\"DUE\",\"base_url\":\"https://app\"}",
            job_type="reminder",
            payload=json.dumps({"invoice_id": 1, "stage": "DUE", "base_url": "https://app"}),
            status="failed",
            attempts=2,
            updated_at=datetime.now(tz=timezone.utc),
        )
        job2 = OutboundJob(
            job_key="reminder:{\"invoice_id\":2,\"stage\":\"+3\",\"base_url\":\"https://app\"}",
            job_type="reminder",
            payload=json.dumps({"invoice_id": 2, "stage": "+3", "base_url": "https://app"}),
            status="skipped",
            attempts=1,
            updated_at=datetime.now(tz=timezone.utc),
        )
        job3 = OutboundJob(
            job_key="reminder:{\"invoice_id\":3,\"stage\":\"+7\",\"base_url\":\"https://app\"}",
            job_type="reminder",
            payload=json.dumps({"invoice_id": 3, "stage": "+7", "base_url": "https://app"}),
            status="succeeded",
            attempts=1,
        )
        session.add(job1)
        session.add(job2)
        session.add(job3)
        session.commit()

    calls: list[tuple[int, str, str]] = []

    def fake_enqueue(invoice_id: int, stage: str, base_url: str) -> None:
        calls.append((invoice_id, stage, base_url))

    summary = requeue_failed_reminders(limit=10, requeue_fn=fake_enqueue)

    assert summary["selected"] == 2
    assert summary["requeued"] == 2
    assert summary["failed"] == 0
    assert calls == [(1, "DUE", "https://app"), (2, "+3", "https://app")]
