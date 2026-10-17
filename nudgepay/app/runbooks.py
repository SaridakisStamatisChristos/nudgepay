"""Utilities for documenting rotation runbooks and dashboard history."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Mapping

from sqlmodel import Session

from .config import get_settings
from .db import engine
from .models import SecretRotationRunbook


def _ensure_session(session: Session | None) -> tuple[Session, Session | None]:
    if session is not None:
        return session, None
    managed = Session(engine)
    return managed, managed


def _format_template(template: str | None, **context: object) -> str | None:
    if not template:
        return None
    try:
        return template.format(**context)
    except Exception:  # pragma: no cover - defensive formatting fallback
        return template


def record_rotation_run(
    *,
    spec: str,
    pattern: str,
    policy: str,
    rotated_at: datetime,
    hook_count: int,
    metadata: Mapping[str, object],
    session: Session | None = None,
) -> SecretRotationRunbook:
    """Persist a rotation run entry for compliance dashboards."""

    managed_session, owned_session = _ensure_session(session)
    try:
        settings = get_settings()
        runbook_url = _format_template(
            getattr(settings, "secret_rotation_runbook_template", None),
            spec=spec,
            pattern=pattern,
            policy=policy,
        )
        dashboard_url = _format_template(
            getattr(settings, "secret_rotation_dashboard_template", None),
            spec=spec,
            pattern=pattern,
            policy=policy,
        )
        entry = SecretRotationRunbook(
            spec=spec,
            pattern=pattern,
            policy=policy,
            rotated_at=rotated_at.astimezone(tz=UTC),
            hook_count=hook_count,
            details={str(key): str(value) for key, value in metadata.items()},
            runbook_url=runbook_url,
            dashboard_url=dashboard_url,
        )
        managed_session.add(entry)
        managed_session.flush()
        managed_session.refresh(entry)
        return entry
    finally:
        if owned_session is not None:
            owned_session.commit()
            owned_session.close()


__all__ = ["record_rotation_run"]
