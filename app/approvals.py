"""Delegated approval workflows for high-risk operations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Iterable

from sqlmodel import Session, select

from .config import get_settings
from .db import engine
from .models import DelegatedApproval


class ApprovalError(RuntimeError):
    """Raised when approval workflows fail."""


def _ensure_session(session: Session | None) -> tuple[Session, Session | None]:
    if session is not None:
        return session, None
    managed = Session(engine)
    return managed, managed


def create_approval(
    *,
    action: str,
    subject: str,
    requested_by: str,
    reason: str | None = None,
    required_approvals: int | None = None,
    ttl_minutes: int | None = None,
    session: Session | None = None,
) -> DelegatedApproval:
    """Create a new delegated approval request."""

    managed_session, owned_session = _ensure_session(session)
    try:
        settings = get_settings()
        approvals_required = required_approvals or getattr(settings, "default_required_approvals", 2)
        expires_at = None
        ttl = ttl_minutes or getattr(settings, "delegated_approval_ttl_minutes", 1440)
        if ttl:
            expires_at = datetime.now(tz=UTC) + timedelta(minutes=ttl)
        record = DelegatedApproval(
            action=action,
            subject=subject,
            requested_by=requested_by,
            reason=reason,
            required_approvals=max(1, approvals_required),
            expires_at=expires_at,
        )
        managed_session.add(record)
        managed_session.flush()
        managed_session.refresh(record)
        return record
    finally:
        if owned_session is not None:
            owned_session.commit()
            owned_session.close()


def _refresh_status(approval: DelegatedApproval) -> None:
    if approval.status not in {"pending", "approved"}:
        return
    now = datetime.now(tz=UTC)
    approval.updated_at = now
    if approval.expires_at and approval.expires_at < now and approval.status == "pending":
        approval.status = "expired"
        approval.resolved_at = now


def approve(
    *,
    approval_id: int,
    approver: str,
    session: Session,
) -> DelegatedApproval:
    approval = session.get(DelegatedApproval, approval_id)
    if approval is None:
        raise ApprovalError(f"Approval {approval_id} not found")
    _refresh_status(approval)
    if approval.status == "expired":
        raise ApprovalError("Approval request has expired")
    if approval.status not in {"pending", "approved"}:
        raise ApprovalError("Approval request is not actionable")
    if approver == approval.requested_by:
        raise ApprovalError("Requesters cannot self-approve")
    if approver in approval.denied_by:
        raise ApprovalError("Approver has already denied the request")
    if approver in approval.approved_by:
        raise ApprovalError("Approver has already approved the request")

    approval.approved_by.append(approver)
    if len(set(approval.approved_by)) >= approval.required_approvals:
        approval.status = "approved"
        approval.resolved_at = datetime.now(tz=UTC)
    else:
        approval.status = "pending"
    approval.updated_at = datetime.now(tz=UTC)
    session.add(approval)
    session.commit()
    session.refresh(approval)
    return approval


def deny(
    *,
    approval_id: int,
    approver: str,
    session: Session,
) -> DelegatedApproval:
    approval = session.get(DelegatedApproval, approval_id)
    if approval is None:
        raise ApprovalError(f"Approval {approval_id} not found")
    _refresh_status(approval)
    if approval.status == "expired":
        raise ApprovalError("Approval request has expired")
    if approval.status not in {"pending", "approved"}:
        raise ApprovalError("Approval request is not actionable")

    approval.denied_by.append(approver)
    approval.status = "denied"
    approval.resolved_at = datetime.now(tz=UTC)
    approval.updated_at = datetime.now(tz=UTC)
    session.add(approval)
    session.commit()
    session.refresh(approval)
    return approval


def require_approved(
    *,
    approval_id: int,
    action: str,
    subject: str,
    session: Session,
) -> DelegatedApproval:
    approval = session.get(DelegatedApproval, approval_id)
    if approval is None:
        raise ApprovalError(f"Approval {approval_id} not found")
    _refresh_status(approval)
    if approval.status != "approved":
        raise ApprovalError("Approval has not been granted")
    if approval.consumed_at is not None:
        raise ApprovalError("Approval has already been consumed")
    if approval.action != action or approval.subject != subject:
        raise ApprovalError("Approval context does not match requested action")
    session.add(approval)
    session.commit()
    session.refresh(approval)
    return approval


def consume(
    approval: DelegatedApproval,
    *,
    session: Session,
) -> DelegatedApproval:
    approval.consumed_at = datetime.now(tz=UTC)
    approval.updated_at = approval.consumed_at
    session.add(approval)
    session.commit()
    session.refresh(approval)
    return approval


def list_pending(session: Session, *, action: str | None = None) -> Iterable[DelegatedApproval]:
    statement = select(DelegatedApproval).where(DelegatedApproval.status == "pending")
    if action:
        statement = statement.where(DelegatedApproval.action == action)
    return session.exec(statement).all()


__all__ = [
    "ApprovalError",
    "create_approval",
    "approve",
    "deny",
    "require_approved",
    "consume",
    "list_pending",
]
