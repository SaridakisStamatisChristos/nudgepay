"""Deployment ledger helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Mapping

from sqlmodel import Session

from .db import engine
from .models import DeploymentRecord


def _ensure_session(session: Session | None) -> tuple[Session, Session | None]:
    if session is not None:
        return session, None
    managed = Session(engine)
    return managed, managed


def start_deployment(
    *,
    environment: str,
    build_sha: str,
    initiated_by: str,
    metadata: Mapping[str, object] | None = None,
    session: Session | None = None,
) -> DeploymentRecord:
    """Create a new deployment ledger entry."""

    managed_session, owned_session = _ensure_session(session)
    try:
        record = DeploymentRecord(
            environment=environment,
            build_sha=build_sha,
            initiated_by=initiated_by,
            attributes={str(k): str(v) for k, v in (metadata or {}).items()},
        )
        managed_session.add(record)
        managed_session.flush()
        managed_session.refresh(record)
        return record
    finally:
        if owned_session is not None:
            owned_session.commit()
            owned_session.close()


def finalize_deployment(
    *,
    deployment_id: int,
    status: str,
    synthetic_gate: str,
    rollback_triggered: bool,
    notes: str | None = None,
    metadata: Mapping[str, object] | None = None,
    session: Session | None = None,
) -> DeploymentRecord:
    """Mark a deployment as complete."""

    managed_session, owned_session = _ensure_session(session)
    try:
        record = managed_session.get(DeploymentRecord, deployment_id)
        if record is None:
            raise LookupError(f"Deployment {deployment_id} not found")

        record.status = status
        record.synthetic_gate = synthetic_gate
        record.rollback_triggered = rollback_triggered
        record.completed_at = datetime.now(tz=UTC)
        record.notes = notes
        if metadata:
            record.attributes.update({str(k): str(v) for k, v in metadata.items()})

        managed_session.add(record)
        managed_session.flush()
        managed_session.refresh(record)
        return record
    finally:
        if owned_session is not None:
            owned_session.commit()
            owned_session.close()


__all__ = ["start_deployment", "finalize_deployment"]
