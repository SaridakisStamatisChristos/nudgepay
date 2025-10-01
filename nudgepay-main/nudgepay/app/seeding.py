"""Seed and validate environment data sets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Iterable, Mapping

import bcrypt
from sqlalchemy import text
from sqlmodel import Session, delete, select

from .db import init_db, session_scope
from .models import AdminUser, Client, Invoice, ReminderLog, User


@dataclass(slots=True)
class SeedSummary:
    """Structured summary describing seeded records and validations."""

    dataset_version: str
    created: dict[str, int]
    backfill: dict[str, int]

    def as_dict(self) -> dict[str, object]:
        return {
            "dataset_version": self.dataset_version,
            "created": dict(self.created),
            "backfill": dict(self.backfill),
        }


DEFAULT_DATASET: dict[str, object] = {
    "version": "2024-09-production-snapshot",
    "admins": [
        {
            "email": "ops@nudgepay.test",
            "password": "Ops!Rotate2024",
            "role": "owner",
            "permissions": ["*"],
            "federated_providers": ["okta"],
        },
        {
            "email": "support@nudgepay.test",
            "password": "SupportR0cks",
            "role": "analyst",
            "permissions": [
                "approvals:read",
                "approvals:approve",
                "service_tokens:issue",
            ],
        },
    ],
    "users": [
        {
            "email": "merchant@nudgepay.test",
            "password": "MerchantSeed!",
            "stripe_account_id": "acct_seed123",
            "clients": [
                {
                    "name": "Acme Manufacturing",
                    "email": "ap@acme.test",
                    "invoices": [
                        {
                            "number": "INV-1001",
                            "amount_cents": 125_00,
                            "currency": "usd",
                            "due_in_days": 7,
                            "status": "Open",
                            "reminders_enabled": True,
                        },
                        {
                            "number": "INV-1002",
                            "amount_cents": 860_00,
                            "currency": "usd",
                            "due_in_days": -3,
                            "status": "Paid",
                            "reminders_enabled": False,
                        },
                    ],
                },
                {
                    "name": "Northwind Analytics",
                    "email": "finance@northwind.test",
                    "invoices": [
                        {
                            "number": "INV-2001",
                            "amount_cents": 4_200_00,
                            "currency": "usd",
                            "due_in_days": 21,
                            "status": "Open",
                            "reminders_enabled": True,
                        }
                    ],
                },
            ],
        },
        {
            "email": "enterprise@nudgepay.test",
            "password": "EnterpriseSeed!",
            "stripe_account_id": "acct_seed987",
            "clients": [
                {
                    "name": "Globex Corp",
                    "email": "controller@globex.test",
                    "invoices": [
                        {
                            "number": "INV-9000",
                            "amount_cents": 18_750_00,
                            "currency": "usd",
                            "due_in_days": 14,
                            "status": "Open",
                            "reminders_enabled": True,
                        },
                        {
                            "number": "INV-9001",
                            "amount_cents": 21_300_00,
                            "currency": "usd",
                            "due_in_days": 45,
                            "status": "Open",
                            "reminders_enabled": True,
                        },
                    ],
                }
            ],
        },
    ],
}


def _hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _reset_tables(session: Session) -> None:
    """Clear existing data so the seed mirrors production snapshots."""

    session.exec(delete(ReminderLog))
    session.exec(delete(Invoice))
    session.exec(delete(Client))
    session.exec(delete(User))
    session.exec(delete(AdminUser))


def _ensure_admin_schema(session: Session) -> None:
    """Add missing admin columns when legacy migrations are incomplete."""

    info = session.exec(text("PRAGMA table_info('adminuser')")).all()
    if not info:
        return
    existing = {row[1] for row in info}
    alterations: dict[str, str] = {
        "role": "ALTER TABLE adminuser ADD COLUMN role TEXT DEFAULT 'viewer'",
        "permissions": "ALTER TABLE adminuser ADD COLUMN permissions TEXT DEFAULT '[]'",
        "external_id": "ALTER TABLE adminuser ADD COLUMN external_id TEXT",
        "federated_providers": "ALTER TABLE adminuser ADD COLUMN federated_providers TEXT DEFAULT '[]'",
        "hardware_key_fingerprints": "ALTER TABLE adminuser ADD COLUMN hardware_key_fingerprints TEXT DEFAULT '[]'",
    }
    for column, statement in alterations.items():
        if column not in existing:
            session.exec(text(statement))


def _seed_admins(session: Session, admins: Iterable[Mapping[str, object]]) -> int:
    created = 0
    for admin in admins:
        record = AdminUser(
            email=str(admin["email"]).strip().lower(),
            password_hash=_hash_password(str(admin["password"])),
            role=str(admin.get("role", "viewer")),
            permissions=list(admin.get("permissions", [])),
            federated_providers=list(admin.get("federated_providers", [])),
        )
        session.add(record)
        created += 1
    return created


def _seed_users(
    session: Session, users: Iterable[Mapping[str, object]]
) -> dict[str, int]:
    user_count = 0
    client_count = 0
    invoice_count = 0

    today = date.today()

    for user in users:
        account = User(
            email=str(user["email"]).strip().lower(),
            password_hash=_hash_password(str(user["password"])),
            stripe_account_id=str(user.get("stripe_account_id", "")) or None,
        )
        session.add(account)
        session.flush()
        user_count += 1

        for client in user.get("clients", []):
            client_record = Client(
                user_id=account.id or 0,
                name=str(client["name"]),
                email=str(client["email"]),
            )
            session.add(client_record)
            session.flush()
            client_count += 1

            for invoice in client.get("invoices", []):
                due_in_days = int(invoice.get("due_in_days", 0))
                due_date = today + timedelta(days=due_in_days)
                invoice_record = Invoice(
                    user_id=account.id or 0,
                    client_id=client_record.id or 0,
                    number=str(invoice["number"]),
                    amount_cents=int(invoice["amount_cents"]),
                    currency=str(invoice.get("currency", "usd")),
                    due_date=due_date,
                    status=str(invoice.get("status", "Open")),
                    reminders_enabled=bool(invoice.get("reminders_enabled", True)),
                )
                session.add(invoice_record)
                invoice_count += 1

    return {
        "users": user_count,
        "clients": client_count,
        "invoices": invoice_count,
    }


def _backfill_reminder_logs(session: Session) -> dict[str, int]:
    inserted = 0
    invoices = session.exec(
        select(Invoice).where(Invoice.reminders_enabled.is_(True))
    ).all()
    for invoice in invoices:
        existing = session.exec(
            select(ReminderLog).where(
                ReminderLog.invoice_id == invoice.id,
                ReminderLog.kind == "seed-validation",
            )
        ).first()
        if existing:
            continue
        session.add(
            ReminderLog(
                invoice_id=invoice.id or 0,
                kind="seed-validation",
                result="recorded",
                details="Synthetic reminder generated during seed backfill",
            )
        )
        inserted += 1
    return {"reminder_logs": inserted}


def seed_environment(
    dataset: Mapping[str, object] | None = None,
    *,
    reset: bool = True,
    apply_backfill: bool = True,
) -> SeedSummary:
    """Seed the environment with a canonical dataset and optional backfill."""

    init_db()
    payload = dataset or DEFAULT_DATASET

    with session_scope() as session:
        if reset:
            _reset_tables(session)

        _ensure_admin_schema(session)

        created_counts = {
            "admins": _seed_admins(session, payload.get("admins", [])),
        }
        created_counts.update(_seed_users(session, payload.get("users", [])))

        backfill_counts = {"reminder_logs": 0}
        if apply_backfill:
            backfill_counts = _backfill_reminder_logs(session)

    return SeedSummary(
        dataset_version=str(payload.get("version", "unknown")),
        created=created_counts,
        backfill=backfill_counts,
    )


def validate_environment(
    dataset: Mapping[str, object] | None = None,
    *,
    session: Session | None = None,
) -> dict[str, object]:
    """Validate the active environment against the canonical dataset."""

    expected = dataset or DEFAULT_DATASET

    expected_counts = {
        "admins": len(expected.get("admins", [])),
        "users": len(expected.get("users", [])),
        "clients": sum(
            len(user.get("clients", [])) for user in expected.get("users", [])
        ),
        "invoices": sum(
            len(client.get("invoices", []))
            for user in expected.get("users", [])
            for client in user.get("clients", [])
        ),
    }

    if session is None:
        context = session_scope()
        managed = context.__enter__()
        close = context.__exit__
    else:
        managed = session
        close = None

    try:
        actual_counts = {
            "admins": len(managed.exec(select(AdminUser)).all()),
            "users": len(managed.exec(select(User)).all()),
            "clients": len(managed.exec(select(Client)).all()),
            "invoices": len(managed.exec(select(Invoice)).all()),
        }
    finally:
        if close is not None:
            close(None, None, None)

    mismatches = {}
    passed_checks = 0
    total_checks = len(expected_counts)

    for key, expected_value in expected_counts.items():
        actual_value = actual_counts.get(key, 0)
        if actual_value == expected_value:
            passed_checks += 1
        else:
            mismatches[key] = {
                "expected": expected_value,
                "actual": actual_value,
            }

    score = passed_checks / total_checks if total_checks else 1.0

    return {
        "dataset_version": str(expected.get("version", "unknown")),
        "expected": expected_counts,
        "actual": actual_counts,
        "mismatches": mismatches,
        "score": round(score, 4),
    }


__all__ = [
    "DEFAULT_DATASET",
    "SeedSummary",
    "seed_environment",
    "validate_environment",
]
