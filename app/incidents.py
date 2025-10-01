"""Incident reporting helpers for webhook anomalies and other events."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Mapping

from sqlmodel import Session

from .automation import dispatch_alert
from .db import engine
from .models import IncidentEvent


def _ensure_session(session: Session | None) -> tuple[Session, Session | None]:
    if session is not None:
        return session, None
    managed = Session(engine)
    return managed, managed


def report_incident(
    *,
    source: str,
    category: str,
    severity: str,
    description: str,
    metadata: Mapping[str, object] | None = None,
    alert: bool = True,
    session: Session | None = None,
) -> IncidentEvent:
    """Persist and optionally fan out an incident record."""

    managed_session, owned_session = _ensure_session(session)
    attributes_dict = {str(k): str(v) for k, v in (metadata or {}).items()}
    try:
        payload = IncidentEvent(
            source=source,
            category=category,
            severity=severity,
            description=description,
            attributes=attributes_dict,
            created_at=datetime.now(tz=UTC),
        )
        managed_session.add(payload)
        managed_session.flush()
        managed_session.refresh(payload)
    finally:
        if owned_session is not None:
            owned_session.commit()
            owned_session.close()

    if alert:
        dispatch_alert(
            f"incident.{category}",
            {
                "source": source,
                "severity": severity,
                "description": description,
                "metadata": dict(attributes_dict),
            },
        )
    return payload


def report_webhook_anomaly(
    *,
    category: str,
    description: str,
    metadata: Mapping[str, object],
    session: Session | None = None,
) -> IncidentEvent:
    """Specialised helper for webhook anomalies."""

    return report_incident(
        source="webhook", category=category, severity="high", description=description, metadata=metadata, session=session
    )


__all__ = ["report_incident", "report_webhook_anomaly"]
