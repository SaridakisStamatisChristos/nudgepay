from datetime import UTC, date, datetime
from typing import Dict, List, Optional

from sqlalchemy import Column, JSON, Text
from sqlmodel import Field, Relationship, SQLModel


def utcnow() -> datetime:
    """Return a timezone-aware timestamp in UTC."""

    return datetime.now(tz=UTC)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    stripe_account_id: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)

class AdminUser(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    totp_secret: Optional[str] = None
    is_active: bool = Field(default=True, index=True)
    role: str = Field(default="viewer", index=True)
    permissions: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, default=list),
    )
    external_id: Optional[str] = Field(default=None, index=True)
    federated_providers: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, default=list),
    )
    hardware_key_fingerprints: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, default=list),
    )
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    last_login_at: Optional[datetime] = None

    def has_permission(self, permission: str) -> bool:
        return permission in set(self.permissions or []) or "*" in set(self.permissions or [])


class Client(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    name: str
    email: str
    created_at: datetime = Field(default_factory=utcnow)
    invoices: List["Invoice"] = Relationship(back_populates="client")

class Invoice(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    client_id: int = Field(foreign_key="client.id", index=True)
    number: str
    amount_cents: int
    currency: str = "usd"
    due_date: date
    status: str = Field(default="Open")  # Open, Paid, Canceled
    stripe_payment_link: Optional[str] = None
    reminders_enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    version: int = Field(default=1, sa_column_kwargs={"nullable": False})
    client: Optional[Client] = Relationship(back_populates="invoices")

class ReminderLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    invoice_id: int = Field(foreign_key="invoice.id", index=True)
    kind: str  # T-3, DUE, +3, +7, manual
    sent_at: datetime = Field(default_factory=utcnow)
    result: str  # queued/sent/failed
    details: Optional[str] = None


class AdminAuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    action: str = Field(index=True)
    actor: str = Field(index=True)
    created_at: datetime = Field(default_factory=utcnow, index=True)
    ip_address: Optional[str] = Field(default=None)
    context: str = Field(default="{}", sa_column=Column(Text, nullable=False, default="{}"))


class ProcessedWebhook(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    provider: str = Field(index=True)
    event_id: str = Field(index=True, unique=True)
    received_at: datetime = Field(default_factory=utcnow)
    payload: str = Field(sa_column=Column(Text, nullable=False))


class OutboundJob(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    job_key: str = Field(index=True, unique=True)
    job_type: str = Field(index=True)
    payload: str = Field(sa_column=Column(Text, nullable=False))
    status: str = Field(default="queued", index=True)
    attempts: int = Field(default=0)
    last_error: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow, index=True)
    updated_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None


class SecretRotationRunbook(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    spec: str = Field(index=True)
    pattern: str = Field(index=True)
    policy: str = Field(index=True)
    rotated_at: datetime = Field(default_factory=utcnow, index=True)
    hook_count: int = Field(default=0)
    details: Dict[str, str] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, default=dict),
    )
    dashboard_url: Optional[str] = None
    runbook_url: Optional[str] = None


class DelegatedApproval(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    action: str = Field(index=True)
    subject: str = Field(index=True)
    status: str = Field(default="pending", index=True)
    requested_by: str = Field(index=True)
    reason: Optional[str] = None
    required_approvals: int = Field(default=2)
    approved_by: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, default=list),
    )
    denied_by: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, default=list),
    )
    created_at: datetime = Field(default_factory=utcnow, index=True)
    updated_at: datetime = Field(default_factory=utcnow)
    resolved_at: Optional[datetime] = Field(default=None, index=True)
    expires_at: Optional[datetime] = Field(default=None, index=True)
    consumed_at: Optional[datetime] = None


class ServiceToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    token_prefix: str = Field(index=True)
    token_hash: str = Field(index=True, unique=True)
    scopes: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, default=list),
    )
    created_by: str = Field(index=True)
    created_at: datetime = Field(default_factory=utcnow, index=True)
    expires_at: Optional[datetime] = Field(default=None, index=True)
    last_used_at: Optional[datetime] = Field(default=None, index=True)
    revoked: bool = Field(default=False, index=True)
    revoked_at: Optional[datetime] = Field(default=None)
    description: Optional[str] = None


class AutomationExecutionRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: str = Field(index=True, unique=True)
    job_name: str = Field(index=True)
    scheduler: Optional[str] = Field(default=None, index=True)
    triggered_by: Optional[str] = None
    ran_at: datetime = Field(default_factory=utcnow, index=True)
    success: bool = Field(default=True, index=True)
    metrics: Dict[str, float] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, default=dict),
    )
    details: Dict[str, str] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, default=dict),
    )


class DeploymentRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    environment: str = Field(index=True)
    build_sha: str = Field(index=True)
    initiated_by: str = Field(index=True)
    status: str = Field(default="in_progress", index=True)
    started_at: datetime = Field(default_factory=utcnow, index=True)
    completed_at: Optional[datetime] = Field(default=None, index=True)
    rollback_triggered: bool = Field(default=False, index=True)
    synthetic_gate: str = Field(default="pending", index=True)
    attributes: Dict[str, str] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, default=dict),
    )
    notes: Optional[str] = None


class IncidentEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source: str = Field(index=True)
    category: str = Field(index=True)
    severity: str = Field(index=True)
    description: str
    attributes: Dict[str, str] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, default=dict),
    )
    created_at: datetime = Field(default_factory=utcnow, index=True)
