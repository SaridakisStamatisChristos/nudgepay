"""FastAPI application entrypoint."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time as time_module
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .admins import (
    AdminAlreadyExistsError,
    deactivate_admin,
    ensure_admin,
    list_admins,
    rotate_password,
)
from .audit import record_admin_event
from .automation import (
    dispatch_alert,
    managed_schedule_payload,
    run_backup_verification,
    run_dlq_reprocessor,
)
from .auth import (
    LoginResult,
    has_permission,
    login as login_action,
    logout as logout_action,
    refresh_session_permissions,
    require_permission,
    session_identity,
)
from .circuit_breaker import CircuitBreaker
from .config import SettingsValidationError, get_settings
from .db import get_session, init_db
from .emailer import send_email
from .logging_utils import setup_logging
from .csrf import render_csrf_input
from .middleware import (
    CSRFMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from .metrics import (
    record_circuit_breaker,
    record_payment,
    record_reminder,
    setup_metrics,
)
from .models import (
    Client,
    DelegatedApproval,
    Invoice,
    ProcessedWebhook,
    ReminderLog,
    ServiceToken,
)
from .payments import ensure_payment_link, verify_webhook
from .scheduler import queue_reminder, run_daily_reminders
from . import approvals, high_risk, incidents, service_tokens

settings = get_settings()
setup_logging(settings.log_level)
logger = logging.getLogger(__name__)

_stripe_breaker = CircuitBreaker(
    "stripe_webhook",
    failure_threshold=settings.stripe_webhook_circuit_threshold,
    reset_after_seconds=settings.stripe_webhook_circuit_ttl_seconds,
)


def _mark_breaker_failure(
    reason: str, metadata: dict[str, object] | None = None
) -> None:
    opened = _stripe_breaker.record_failure()
    record_circuit_breaker("stripe_webhook", "failure")
    if opened:
        record_circuit_breaker("stripe_webhook", "open")
        dispatch_alert(
            "stripe_webhook_circuit_open",
            {
                "reason": reason,
                "metadata": dict(metadata or {}),
            },
        )


def _mark_breaker_success(context: str) -> None:
    was_open = _stripe_breaker.is_open()
    _stripe_breaker.record_success()
    record_circuit_breaker("stripe_webhook", "success")
    if was_open:
        record_circuit_breaker("stripe_webhook", "closed")
        dispatch_alert(
            "stripe_webhook_circuit_closed",
            {
                "context": context,
            },
        )


try:
    validation_result = settings.ensure_valid(
        strict=settings.environment in {"staging", "production"}
    )
except SettingsValidationError as exc:  # pragma: no cover - configuration must be fixed
    logger.critical("Invalid configuration detected: %s", exc)
    raise
else:
    for warning in validation_result.warnings:
        logger.warning("Configuration warning: %s", warning)
    for error in validation_result.errors:
        logger.error("Configuration issue: %s", error)

app = FastAPI(title="NudgePay", debug=settings.debug)
app.state.settings = settings
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site=settings.session_cookie_same_site,
    https_only=settings.session_https_only,
    session_cookie=settings.session_cookie_name,
    max_age=settings.session_cookie_ttl_seconds,
)
# Install CSRF middleware after sessions so tokens bind to the authenticated session.
app.add_middleware(CSRFMiddleware)
app.add_middleware(
    RequestContextMiddleware,
    header_name=settings.request_id_header,
)
app.add_middleware(
    SecurityHeadersMiddleware,
    content_security_policy=settings.content_security_policy,
    hsts_seconds=settings.hsts_seconds,
    force_https=settings.session_https_only,
)
app.add_middleware(GZipMiddleware, minimum_size=512)
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
if settings.allowed_hosts and settings.allowed_hosts != ("*",):
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts)
    )

setup_metrics(
    app,
    enabled=settings.metrics_enabled,
    endpoint=settings.metrics_endpoint,
    prefix=settings.metrics_prefix,
)

BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals["csrf_input"] = render_csrf_input
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def _admin_actor(request: Request) -> str:
    return request.session.get("admin_email", settings.admin_email)


def _request_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _serialize_approval(record: DelegatedApproval) -> Dict[str, object]:
    return {
        "id": record.id,
        "action": record.action,
        "subject": record.subject,
        "status": record.status,
        "requested_by": record.requested_by,
        "reason": record.reason,
        "required_approvals": record.required_approvals,
        "approved_by": list(record.approved_by or []),
        "denied_by": list(record.denied_by or []),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "resolved_at": record.resolved_at.isoformat() if record.resolved_at else None,
        "consumed_at": record.consumed_at.isoformat() if record.consumed_at else None,
    }


def _serialize_service_token(record: ServiceToken) -> Dict[str, object]:
    return {
        "id": record.id,
        "name": record.name,
        "token_prefix": record.token_prefix,
        "scopes": list(record.scopes or []),
        "created_by": record.created_by,
        "created_at": record.created_at.isoformat(),
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "last_used_at": (
            record.last_used_at.isoformat() if record.last_used_at else None
        ),
        "revoked": record.revoked,
        "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
        "description": record.description,
    }


@app.on_event("startup")
def on_startup() -> None:
    logger.info("Initializing database")
    init_db()


# ---------- Platform ----------
@app.get("/healthz", response_class=PlainTextResponse)
def health_check(session: Session = Depends(get_session)) -> PlainTextResponse:
    """Liveness endpoint validating database connectivity."""

    session.exec(select(Invoice.id).limit(1))
    return PlainTextResponse("ok")


# ---------- Helpers ----------
def _day_bounds(target_day: date) -> Tuple[datetime, datetime]:
    start = datetime.combine(target_day, time.min, tzinfo=UTC)
    end = datetime.combine(target_day, time.max, tzinfo=UTC)
    return start, end


def _ensure_utc(value: datetime | None) -> datetime | None:
    """Normalize ``value`` so comparisons against UTC-aware bounds succeed."""

    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def get_last_7_days_stats(
    session: Session,
) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    today = date.today()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    start_window, _ = _day_bounds(days[0])
    _, end_window = _day_bounds(days[-1])

    logs = session.exec(
        select(ReminderLog).where(ReminderLog.sent_at.between(start_window, end_window))
    ).all()
    invoices_paid = session.exec(
        select(Invoice).where(
            Invoice.status == "Paid",
            Invoice.updated_at.is_not(None),
            Invoice.updated_at.between(start_window, end_window),
        )
    ).all()

    series: List[Dict[str, object]] = []
    for day in days:
        start, end = _day_bounds(day)
        nudges = 0
        for log in logs:
            sent_at = _ensure_utc(log.sent_at)
            if sent_at and start <= sent_at <= end:
                nudges += 1
        paid = 0
        for inv in invoices_paid:
            updated_at = _ensure_utc(inv.updated_at)
            if updated_at and start <= updated_at <= end:
                paid += 1
        series.append({"date": day.isoformat(), "nudges": nudges, "paid": paid})

    totals = {
        "nudges_7d": sum(item["nudges"] for item in series),
        "paid_7d": sum(item["paid"] for item in series),
    }
    return series, totals


# ---------- Auth ----------
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": None,
            "totp_required": bool(settings.admin_totp_secret),
            "hardware_required": bool(settings.admin_hardware_fingerprints),
            "retry_after": None,
        },
    )


@app.post("/login")
async def login_post(
    request: Request, session: Session = Depends(get_session)
) -> Response:
    form = await request.form()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "")
    totp_code = form.get("totp_code") or None
    hardware_assertion = (form.get("hardware_assertion") or "") or request.headers.get(
        "X-Hardware-Assertion"
    )
    result: LoginResult = login_action(
        request,
        email,
        password,
        totp_code=totp_code,
        hardware_assertion=hardware_assertion or None,
        session=session,
    )
    if result.success:
        return RedirectResponse("/", status_code=303)

    headers: dict[str, str] = {}
    status_code = 200
    if result.retry_after:
        headers["Retry-After"] = str(result.retry_after)
        status_code = 429

    message = result.error or "Invalid credentials"
    if result.retry_after:
        message = f"{message} (retry in {result.retry_after} seconds)"

    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": message,
            "totp_required": bool(settings.admin_totp_secret),
            "hardware_required": bool(settings.admin_hardware_fingerprints),
            "retry_after": result.retry_after,
        },
        status_code=status_code,
        headers=headers or None,
    )


@app.post("/session/refresh", response_class=JSONResponse)
def refresh_session_endpoint(
    request: Request, session: Session = Depends(get_session)
) -> JSONResponse:
    refreshed_at = datetime.now(tz=UTC).isoformat()

    # Always refresh permissions first so bootstrap or newly granted sessions
    # resolve to their latest roles before we evaluate authentication flags.
    refreshed = refresh_session_permissions(request, session=session)
    identity = session_identity(request, permissions=refreshed)

    payload = {
        "permissions": list(identity.permissions),
        "role": identity.role,
        "admin_email": identity.email,
        "refreshed_at": refreshed_at,
    }

    # Unauthenticated sessions still return 200 with empty permissions (test
    # expectation) while authenticated identities surface their email/role.
    if not identity.authenticated:
        payload["permissions"] = []
        payload.setdefault("role", None)
        payload.setdefault("admin_email", None)

    return JSONResponse(payload, status_code=status.HTTP_200_OK)


@app.post("/logout")
def logout_post(request: Request) -> RedirectResponse:
    return logout_action(request)


# ---------- Root (Landing or Dashboard) ----------
@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request, session: Session = Depends(get_session)
) -> HTMLResponse:
    if not request.session.get("authed"):
        return templates.TemplateResponse(request, "marketing.html", {})
    total_open = session.exec(select(Invoice).where(Invoice.status == "Open")).all()
    total_paid = session.exec(select(Invoice).where(Invoice.status == "Paid")).all()
    recent = session.exec(select(Invoice).order_by(Invoice.created_at.desc())).all()[
        :10
    ]
    series, totals = get_last_7_days_stats(session)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "open_count": len(total_open),
            "paid_count": len(total_paid),
            "open_sum": sum(i.amount_cents for i in total_open) / 100,
            "paid_sum": sum(i.amount_cents for i in total_paid) / 100,
            "invoices": recent,
            "series": series,
            "totals": totals,
        },
    )


# ---------- Clients ----------
@app.get(
    "/clients",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("invoice:read"))],
)
def list_clients(
    request: Request, session: Session = Depends(get_session)
) -> HTMLResponse:
    clients = session.exec(select(Client).order_by(Client.created_at.desc())).all()
    return templates.TemplateResponse(request, "clients.html", {"clients": clients})


@app.post(
    "/clients",
    dependencies=[Depends(require_permission("invoice:write"))],
)
def create_client(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    client = Client(name=name, email=email, user_id=1)
    session.add(client)
    session.flush()
    record_admin_event(
        "client.create",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"client_id": client.id, "email": email},
        session=session,
    )
    session.commit()
    logger.info("Client %s created", client.id)
    return RedirectResponse("/clients", status_code=303)


# ---------- Admins ----------
@app.get(
    "/admins",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("admin:manage"))],
)
def admin_index(
    request: Request, session: Session = Depends(get_session)
) -> HTMLResponse:
    admins = list_admins(session)
    return templates.TemplateResponse(request, "admin_users.html", {"admins": admins})


@app.post(
    "/admins",
    dependencies=[Depends(require_permission("admin:manage"))],
)
def admin_create(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
) -> Response:
    try:
        admin = ensure_admin(session, email=email, password=password)
    except AdminAlreadyExistsError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_admin_event(
        "admin.invite",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"email": admin.email},
        session=session,
    )
    logger.info("Admin %s invited", admin.email)
    return RedirectResponse("/admins", status_code=303)


@app.post(
    "/admins/{admin_id}/rotate",
    dependencies=[Depends(require_permission("security:rotate-secrets"))],
)
def admin_rotate(
    request: Request,
    admin_id: int,
    approval_id: int | None = Query(default=None, alias="approval_id"),
    session: Session = Depends(get_session),
) -> PlainTextResponse:
    high_risk.authorize_high_risk_action(
        request,
        session=session,
        action="admin.rotate_password",
        subject=str(admin_id),
        approval_id=approval_id,
    )
    new_password = secrets.token_urlsafe(16)
    admin = rotate_password(session, admin_id=admin_id, new_password=new_password)
    record_admin_event(
        "admin.rotate_password",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"admin_id": admin_id, "email": admin.email},
        session=session,
    )
    logger.info("Admin %s password rotated", admin.email)
    return PlainTextResponse(f"New password for {admin.email}: {new_password}")


@app.post(
    "/admins/{admin_id}/disable",
    dependencies=[Depends(require_permission("admin:manage"))],
)
def admin_disable(
    request: Request,
    admin_id: int,
    session: Session = Depends(get_session),
) -> PlainTextResponse:
    admin = deactivate_admin(session, admin_id=admin_id)
    record_admin_event(
        "admin.disable",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"admin_id": admin_id, "email": admin.email},
        session=session,
    )
    logger.info("Admin %s disabled", admin.email)
    return PlainTextResponse("DISABLED")


# ---------- Delegated approvals & service tokens ----------
@app.get(
    "/approvals",
    response_class=JSONResponse,
    dependencies=[Depends(require_permission("admin:manage"))],
)
def list_approvals(session: Session = Depends(get_session)) -> JSONResponse:
    records = session.exec(
        select(DelegatedApproval).order_by(DelegatedApproval.created_at.desc())
    ).all()
    return JSONResponse(
        {"approvals": [_serialize_approval(record) for record in records]}
    )


@app.post(
    "/approvals",
    response_class=JSONResponse,
    dependencies=[Depends(require_permission("admin:manage"))],
)
def create_approval_request(
    request: Request,
    action: str = Form(...),
    subject: str = Form(...),
    reason: str | None = Form(None),
    required_approvals: int | None = Form(None),
    ttl_minutes: int | None = Form(None),
    session: Session = Depends(get_session),
) -> JSONResponse:
    approval = approvals.create_approval(
        action=action,
        subject=subject,
        requested_by=_admin_actor(request),
        reason=reason,
        required_approvals=required_approvals,
        ttl_minutes=ttl_minutes,
        session=session,
    )
    session.commit()
    session.refresh(approval)
    record_admin_event(
        "approval.request",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={
            "approval_id": approval.id,
            "action": approval.action,
            "subject": approval.subject,
        },
        session=session,
    )
    return JSONResponse(
        _serialize_approval(approval), status_code=status.HTTP_201_CREATED
    )


@app.post(
    "/approvals/{approval_id}/approve",
    response_class=JSONResponse,
    dependencies=[Depends(require_permission("admin:manage"))],
)
def approve_approval(
    request: Request,
    approval_id: int,
    session: Session = Depends(get_session),
) -> JSONResponse:
    approval = approvals.approve(
        approval_id=approval_id,
        approver=_admin_actor(request),
        session=session,
    )
    record_admin_event(
        "approval.approve",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"approval_id": approval.id, "status": approval.status},
        session=session,
    )
    return JSONResponse(_serialize_approval(approval))


@app.post(
    "/approvals/{approval_id}/deny",
    response_class=JSONResponse,
    dependencies=[Depends(require_permission("admin:manage"))],
)
def deny_approval(
    request: Request,
    approval_id: int,
    session: Session = Depends(get_session),
) -> JSONResponse:
    approval = approvals.deny(
        approval_id=approval_id,
        approver=_admin_actor(request),
        session=session,
    )
    record_admin_event(
        "approval.deny",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"approval_id": approval.id, "status": approval.status},
        session=session,
    )
    return JSONResponse(_serialize_approval(approval))


@app.get(
    "/service-tokens",
    response_class=JSONResponse,
    dependencies=[Depends(require_permission("security:rotate-secrets"))],
)
def list_service_tokens(session: Session = Depends(get_session)) -> JSONResponse:
    tokens = session.exec(
        select(ServiceToken).order_by(ServiceToken.created_at.desc())
    ).all()
    return JSONResponse(
        {"tokens": [_serialize_service_token(token) for token in tokens]}
    )


@app.post(
    "/service-tokens",
    response_class=JSONResponse,
    dependencies=[Depends(require_permission("security:rotate-secrets"))],
)
def create_service_token_endpoint(
    request: Request,
    name: str = Form(...),
    scopes: str = Form(...),
    description: str | None = Form(None),
    ttl_minutes: int | None = Form(None),
    session: Session = Depends(get_session),
) -> JSONResponse:
    scope_values = [scope.strip() for scope in scopes.split(",") if scope.strip()]
    token_value, record = service_tokens.create_service_token(
        name=name,
        scopes=scope_values,
        created_by=_admin_actor(request),
        description=description,
        ttl_minutes=ttl_minutes,
        session=session,
    )
    session.commit()
    session.refresh(record)
    record_admin_event(
        "service_token.issue",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"token_id": record.id, "scopes": scope_values},
        session=session,
    )
    body = _serialize_service_token(record)
    body["token"] = token_value
    return JSONResponse(body, status_code=status.HTTP_201_CREATED)


@app.post(
    "/service-tokens/{token_id}/revoke",
    response_class=JSONResponse,
    dependencies=[Depends(require_permission("security:rotate-secrets"))],
)
def revoke_service_token_endpoint(
    request: Request,
    token_id: int,
    session: Session = Depends(get_session),
) -> JSONResponse:
    record = service_tokens.revoke_service_token(token_id=token_id, session=session)
    session.commit()
    session.refresh(record)
    record_admin_event(
        "service_token.revoke",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"token_id": record.id},
        session=session,
    )
    return JSONResponse(_serialize_service_token(record))


# ---------- Invoices ----------
@app.get(
    "/invoices",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("invoice:read"))],
)
def list_invoices(
    request: Request, session: Session = Depends(get_session)
) -> HTMLResponse:
    invoices = session.exec(select(Invoice).order_by(Invoice.created_at.desc())).all()
    return templates.TemplateResponse(request, "invoices.html", {"invoices": invoices})


@app.post(
    "/invoices",
    dependencies=[Depends(require_permission("invoice:write"))],
)
def create_invoice(
    request: Request,
    client_id: int = Form(...),
    number: str = Form(...),
    amount_cents: int = Form(...),
    due_date: date = Form(...),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    invoice = Invoice(
        user_id=1,
        client_id=client_id,
        number=number,
        amount_cents=amount_cents,
        due_date=due_date,
    )
    session.add(invoice)
    session.flush()
    record_admin_event(
        "invoice.create",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={
            "invoice_id": invoice.id,
            "client_id": client_id,
            "amount_cents": amount_cents,
        },
        session=session,
    )
    session.commit()
    try:
        link = ensure_payment_link(
            invoice.amount_cents,
            invoice.currency,
            invoice.number,
            {"invoice_id": str(invoice.id)},
        )
        invoice.stripe_payment_link = link
        session.add(invoice)
        session.commit()
        logger.info("Payment link created for invoice %s", invoice.id)
    except Exception:  # pragma: no cover - depends on Stripe API
        logger.exception("Unable to attach payment link to invoice %s", invoice.id)
    return RedirectResponse("/invoices", status_code=303)


@app.post(
    "/invoices/{invoice_id}/toggle-reminders",
    dependencies=[Depends(require_permission("invoice:write"))],
)
def toggle_reminders(
    request: Request,
    invoice_id: int,
    version: int = Form(...),
    session: Session = Depends(get_session),
) -> PlainTextResponse:
    if not has_permission(request, "invoice:write", session=session):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    invoice = session.get(Invoice, invoice_id)
    if not invoice:
        raise HTTPException(404)
    if invoice.version != version:
        raise HTTPException(
            status_code=409, detail="Invoice changed; refresh and retry"
        )
    invoice.reminders_enabled = not invoice.reminders_enabled
    invoice.version += 1
    invoice.updated_at = datetime.now(tz=UTC)
    session.add(invoice)
    record_admin_event(
        "invoice.toggle_reminders",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"invoice_id": invoice_id, "enabled": invoice.reminders_enabled},
        session=session,
    )
    session.commit()
    logger.info(
        "Invoice %s reminders toggled to %s", invoice_id, invoice.reminders_enabled
    )
    return PlainTextResponse("OK")


@app.post(
    "/invoices/{invoice_id}/send-nudge",
    dependencies=[Depends(require_permission("queue:manage"))],
)
def send_nudge(
    request: Request,
    invoice_id: int,
    version: int = Form(...),
    session: Session = Depends(get_session),
) -> PlainTextResponse:
    # Ensure 403 even if dependency chain is bypassed
    if not has_permission(request, "queue:manage", session=session):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    invoice = session.get(Invoice, invoice_id)
    if not invoice or invoice.status != "Open":
        raise HTTPException(404)
    if invoice.version != version:
        raise HTTPException(
            status_code=409, detail="Invoice changed; refresh and retry"
        )
    recipient: str | None = None
    if invoice.client and invoice.client.email:
        recipient = invoice.client.email
    elif invoice.client_id:
        client = session.get(Client, invoice.client_id)
        if client:
            recipient = client.email
    invoice.version += 1
    invoice.updated_at = datetime.now(tz=UTC)
    queue_reminder(
        invoice,
        "manual",
        settings.base_url,
        session,
        to=recipient,
    )
    record_reminder(stage="manual", status="sent")

    if recipient:
        try:
            send_email(
                recipient,
                subject=f"Payment reminder for invoice #{invoice.id}",
                html=(
                    "<p>Hello,</p>"
                    f"<p>Please review your invoice <strong>#{invoice.id}</strong>.</p>"
                ),
                invoice_id=invoice.id,
                stage="manual",
            )
        except Exception:  # pragma: no cover - defensive around email transport
            logger.warning(
                "Email dispatch failed for invoice %s", invoice.id, exc_info=True
            )
    record_admin_event(
        "invoice.manual_nudge",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"invoice_id": invoice_id, "recipient": recipient},
        session=session,
    )
    session.commit()
    logger.info("Manual nudge queued for invoice %s", invoice_id)
    return PlainTextResponse("SENT")


@app.get("/pay/{invoice_id}", response_class=HTMLResponse)
def invoice_view(
    invoice_id: int, request: Request, session: Session = Depends(get_session)
) -> HTMLResponse:
    invoice = session.get(Invoice, invoice_id)
    if not invoice:
        raise HTTPException(404)
    pay_url = invoice.stripe_payment_link or "#"
    return templates.TemplateResponse(
        request,
        "invoice_view.html",
        {"inv": invoice, "pay_url": pay_url},
    )


# ---------- Settings ----------
@app.get(
    "/settings",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("settings:manage"))],
)
def settings_view(request: Request) -> HTMLResponse:
    cron_url = f"{settings.base_url.rstrip('/')}/internal/run-reminders"
    webhook_url = f"{settings.base_url.rstrip('/')}/webhooks/stripe"
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "cron_url": cron_url,
            "webhook_url": webhook_url,
            "base_url": settings.base_url,
        },
    )


@app.post(
    "/settings/test-email",
    dependencies=[Depends(require_permission("settings:manage"))],
)
def settings_test_email(request: Request) -> PlainTextResponse:
    send_email(settings.admin_email, "NudgePay • Test email", "<p>It works! ✅</p>")
    record_admin_event(
        "settings.test_email",
        actor=_admin_actor(request),
        ip_address=_request_ip(request),
        metadata={"recipient": settings.admin_email},
    )
    return PlainTextResponse("SENT")


# ---------- Internal Cron ----------
def _validate_cron_request(request: Request, *, body: bytes) -> None:
    legacy_key = request.headers.get("X-Cron-Key")
    if legacy_key and hmac.compare_digest(legacy_key, settings.cron_secret):
        logger.warning("Legacy cron key usage detected; migrate to signed requests.")
        return

    signature = request.headers.get("X-Cron-Signature")
    timestamp_header = request.headers.get("X-Cron-Timestamp")
    if not signature or not timestamp_header:
        raise HTTPException(
            status_code=401, detail="Missing cron authentication headers"
        )
    try:
        timestamp = int(timestamp_header)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid timestamp header") from exc
    if abs(time_module.time() - timestamp) > settings.cron_signature_ttl_seconds:
        raise HTTPException(status_code=401, detail="Cron signature expired")

    digest = hashlib.sha256(body or b"").hexdigest()
    payload = f"{timestamp_header}.{digest}".encode("utf-8")
    expected = hmac.new(
        settings.cron_hmac_secret.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid cron signature")

    if settings.cron_mutual_tls_required:
        fingerprint = (
            (request.headers.get("X-Client-Cert-Thumbprint") or "").strip().lower()
        )
        if not fingerprint:
            raise HTTPException(status_code=401, detail="Client certificate required")
        allowed = {fp.lower() for fp in settings.cron_mutual_tls_fingerprints}
        if fingerprint not in allowed:
            raise HTTPException(
                status_code=403, detail="Client certificate not authorized"
            )


def _validate_webhook_request(request: Request, payload: bytes) -> None:
    if not settings.webhook_shared_secret:
        return
    signature = request.headers.get("X-Nudgepay-Signature")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing webhook signature")
    expected = hmac.new(
        settings.webhook_shared_secret.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


@app.post("/internal/run-reminders")
async def run_reminders(request: Request) -> Dict[str, str]:
    body = await request.body()
    _validate_cron_request(request, body=body)
    run_daily_reminders(settings.base_url)
    logger.info("Daily reminders triggered via internal endpoint")
    return {"status": "queued"}


@app.post("/internal/automation/dlq")
async def automation_dlq(request: Request) -> Dict[str, object]:
    body = await request.body()
    _validate_cron_request(request, body=body)
    execution = run_dlq_reprocessor()
    return {
        "success": execution.success,
        "details": execution.details,
        "ran_at": execution.ran_at.isoformat(),
    }


@app.post("/internal/automation/backups")
async def automation_backups(request: Request) -> Dict[str, object]:
    body = await request.body()
    _validate_cron_request(request, body=body)
    execution = run_backup_verification()
    return {
        "success": execution.success,
        "details": execution.details,
        "ran_at": execution.ran_at.isoformat(),
    }


@app.get("/internal/automation/schedules")
async def automation_schedules(request: Request) -> Dict[str, object]:
    _validate_cron_request(request, body=b"")
    return {"schedules": managed_schedule_payload()}


# ---------- Stripe Webhook ----------
@app.post("/webhooks/stripe", response_model=None)
async def stripe_webhook(
    request: Request, session: Session = Depends(get_session)
) -> Response:
    if _stripe_breaker.is_open():
        incidents.report_webhook_anomaly(
            category="circuit_open",
            description="Stripe webhook circuit breaker open",
            metadata={"path": str(request.url)},
        )
        logger.error("Stripe webhook circuit breaker is open; rejecting request")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook temporarily unavailable",
        )

    payload = await request.body()
    try:
        _validate_webhook_request(request, payload)
    except HTTPException as exc:
        _mark_breaker_failure(
            "signature_failure",
            {"detail": exc.detail or "invalid"},
        )
        incidents.report_webhook_anomaly(
            category="signature_failure",
            description="Webhook signature validation failed",
            metadata={"detail": exc.detail or "invalid"},
        )
        raise

    sig = request.headers.get("stripe-signature")
    try:
        event = verify_webhook(sig, payload)
    except Exception as exc:
        _mark_breaker_failure(
            "verification_failure",
            {"error": str(exc)},
        )
        logger.warning("Stripe webhook verification failed: %s", exc)
        incidents.report_webhook_anomaly(
            category="verification_failure",
            description="Webhook verification failed",
            metadata={"error": str(exc)},
        )
        raise HTTPException(status_code=400, detail="Invalid signature") from exc

    event_type = event.get("type") or ""
    if event_type not in settings.stripe_webhook_allowed_events:
        logger.warning("Ignoring unsupported Stripe event %s", event_type)
        _mark_breaker_success("event_ignored")
        return JSONResponse(
            {
                "received": False,
                "ignored": True,
                "reason": "event_not_allowed",
            },
            status_code=status.HTTP_202_ACCEPTED,
        )

    logger.debug(
        "Stripe event received: %s", json.dumps(event.get("data", {}), default=str)
    )
    data = (event.get("data") or {}).get("object", {})
    event_id = event.get("id")

    try:
        if event_id:
            existing = session.exec(
                select(ProcessedWebhook).where(ProcessedWebhook.event_id == event_id)
            ).first()
            if existing:
                logger.info("Duplicate Stripe webhook %s ignored", event_id)
                _mark_breaker_success("duplicate")
                incidents.report_webhook_anomaly(
                    category="duplicate",
                    description="Duplicate webhook ignored",
                    metadata={"event_id": event_id},
                )
                return JSONResponse({"received": True, "duplicate": True})

        meta = data.get("metadata", {}) or {}
        invoice_id = meta.get("invoice_id")

        if invoice_id:
            invoice = session.get(Invoice, int(invoice_id))
            if invoice:
                invoice.status = "Paid"
                invoice.updated_at = datetime.now(tz=UTC)
                invoice.version += 1
                session.add(invoice)
                record_payment("stripe_webhook")
                logger.info(
                    "Invoice %s marked as paid via webhook (event %s)",
                    invoice_id,
                    event_type,
                )

        if event_id:
            session.add(
                ProcessedWebhook(
                    provider="stripe",
                    event_id=event_id,
                    payload=payload.decode("utf-8", errors="ignore"),
                )
            )
        session.commit()
    except HTTPException:
        _mark_breaker_failure(
            "processing_http_exception",
            {"event_id": event_id or "unknown"},
        )
        raise
    except Exception as exc:  # pragma: no cover - depends on database availability
        _mark_breaker_failure(
            "processing_error",
            {"event_id": event_id or "unknown", "error": str(exc)},
        )
        logger.exception("Unexpected error processing Stripe webhook %s", event_id)
        incidents.report_webhook_anomaly(
            category="processing_error",
            description="Webhook processing error",
            metadata={"event_id": event_id or "unknown", "error": str(exc)},
        )
        raise HTTPException(
            status_code=500, detail="Stripe webhook processing failed"
        ) from exc

    _mark_breaker_success("processed")
    return JSONResponse({"received": True})


__all__ = ["app"]
