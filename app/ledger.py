"""Auditable ledgers for automation jobs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Mapping
from uuid import uuid4

from sqlmodel import Session

from .db import engine
from .models import AutomationExecutionRecord


def _ensure_session(session: Session | None) -> tuple[Session, Session | None]:
    if session is not None:
        return session, None
    managed = Session(engine)
    return managed, managed


def record_automation_execution(
    *,
    job_name: str,
    ran_at: datetime,
    success: bool,
    metrics: Mapping[str, object],
    details: Mapping[str, object],
    scheduler: str | None = None,
    triggered_by: str | None = None,
    run_id: str | None = None,
    session: Session | None = None,
) -> AutomationExecutionRecord:
    """Persist a job execution entry."""

    managed_session, owned_session = _ensure_session(session)
    try:
        run_identifier = run_id or str(uuid4())
        payload = AutomationExecutionRecord(
            run_id=run_identifier,
            job_name=job_name,
            scheduler=scheduler,
            triggered_by=triggered_by,
            ran_at=ran_at.astimezone(tz=UTC),
            success=success,
            metrics={
                str(key): float(value)
                for key, value in metrics.items()
                if isinstance(value, (int, float))
            },
            details={str(key): str(value) for key, value in details.items()},
        )
        managed_session.add(payload)
        managed_session.flush()
        managed_session.refresh(payload)
        return payload
    finally:
        if owned_session is not None:
            owned_session.commit()
            owned_session.close()


__all__ = ["record_automation_execution"]
