"""Reminder scheduling utilities."""

from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Optional

from sqlmodel import Session, select

from .db import session_scope
from .models import Invoice
from .tasks import enqueue_reminder

logger = logging.getLogger(__name__)


def compute_stage(due: date, today: date) -> Optional[str]:
    if today == due - timedelta(days=3):
        return "T-3"
    if today == due:
        return "DUE"
    if today == due + timedelta(days=3):
        return "+3"
    if today == due + timedelta(days=7):
        return "+7"
    return None


def queue_reminder(
    inv: Invoice,
    stage: str,
    base_url: str,
    session: Session,
    *,
    to: str | None = None,
) -> None:
    del session  # reminders are handled asynchronously
    job = enqueue_reminder(
        inv.id,
        stage,
        base_url,
        force_inline=(stage == "manual"),
        to=to,
    )
    if job is None:
        logger.info("Reminder for invoice %s processed inline (stage=%s)", inv.id, stage)
    else:
        logger.info("Reminder job queued for invoice %s (stage=%s)", inv.id, stage)


def run_daily_reminders(base_url: str, today: Optional[date] = None) -> None:
    today = today or date.today()
    with session_scope() as session:
        invoices = session.exec(
            select(Invoice).where(Invoice.status == "Open", Invoice.reminders_enabled)
        ).all()
        for inv in invoices:
            stage = compute_stage(inv.due_date, today)
            if stage:
                queue_reminder(inv, stage, base_url, session)
        session.commit()


__all__ = ["compute_stage", "queue_reminder", "run_daily_reminders"]
