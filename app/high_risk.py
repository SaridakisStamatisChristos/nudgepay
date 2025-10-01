"""Authorization helpers for high-risk admin actions."""

from __future__ import annotations

from typing import Any, Mapping

from fastapi import HTTPException, Request, status
from sqlmodel import Session

from . import approvals, service_tokens


def authorize_high_risk_action(
    request: Request,
    *,
    session: Session,
    action: str,
    subject: str,
    approval_id: int | None = None,
) -> Mapping[str, Any]:
    """Ensure a high-risk action has delegated approval or service token authorization."""

    token = request.headers.get("X-Service-Token")
    if token:
        try:
            record = service_tokens.validate_service_token(token, scope=action, session=session)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {"authorized_via": "service_token", "token": record.name}

    resolved_approval = approval_id
    if resolved_approval is None:
        header_value = request.headers.get("X-Approval-ID")
        if header_value and header_value.isdigit():
            resolved_approval = int(header_value)

    if resolved_approval is not None:
        try:
            approval = approvals.require_approved(
                approval_id=resolved_approval,
                action=action,
                subject=subject,
                session=session,
            )
        except approvals.ApprovalError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        approvals.consume(approval, session=session)
        return {"authorized_via": "delegated_approval", "approval_id": approval.id}

    raise HTTPException(
        status_code=status.HTTP_428_PRECONDITION_REQUIRED,
        detail="High-risk action requires a delegated approval or service token",
    )


__all__ = ["authorize_high_risk_action"]
