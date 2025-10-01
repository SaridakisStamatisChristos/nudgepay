"""Audit logging helpers for administrative activity."""

from __future__ import annotations

import json
import logging
from typing import Any, Mapping

from sqlmodel import Session

from .db import session_scope
from .models import AdminAuditLog

logger = logging.getLogger("nudgepay.audit")


def record_admin_event(
    action: str,
    *,
    actor: str,
    ip_address: str | None,
    metadata: Mapping[str, Any] | None = None,
    session: Session | None = None,
) -> None:
    """Persist an audit trail event for sensitive operations."""

    metadata_payload = dict(metadata or {})
    entry = AdminAuditLog(
        action=action,
        actor=actor,
        ip_address=ip_address,
        context=json.dumps(metadata_payload, sort_keys=True),
    )

    if session is not None:
        session.add(entry)
        session.flush()
        logger.info(
            "audit", extra={"action": action, "actor": actor, "ip": ip_address, "context": metadata_payload}
        )
        return

    with session_scope() as scoped_session:
        scoped_session.add(entry)
        scoped_session.commit()
        logger.info(
            "audit",
            extra={"action": action, "actor": actor, "ip": ip_address, "context": metadata_payload},
        )


__all__ = ["record_admin_event"]
