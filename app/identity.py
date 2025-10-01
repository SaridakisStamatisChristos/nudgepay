"""Identity federation, SCIM provisioning, and hardware-key helpers."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Callable, Mapping, MutableMapping, Sequence

from sqlmodel import Session, select

from .admins import AdminAlreadyExistsError, assign_role, ensure_admin
from .audit import record_admin_event
from .models import AdminUser

logger = logging.getLogger(__name__)


def _generate_placeholder_password(label: str) -> str:
    token = secrets.token_urlsafe(16)
    return f"{label}-{token}"


@dataclass(slots=True, frozen=True)
class FederationProvider:
    """Represents an external identity provider used for SSO."""

    slug: str
    issuer: str
    audience: str
    default_role: str = "viewer"
    role_claim: str = "role"
    email_claim: str = "email"
    extra_claims: Sequence[str] = ()
    role_mapping: Mapping[str, str] = field(default_factory=dict)
    health_check: Callable[[Mapping[str, object]], bool] | None = None


@dataclass(slots=True)
class FederationResult:
    """Outcome of processing a federated login assertion."""

    admin: AdminUser
    provider: str
    created: bool


@dataclass(slots=True)
class SCIMEvent:
    """Normalized representation of a SCIM provisioning delta."""

    identifier: str
    email: str
    active: bool = True
    role: str = "viewer"
    permissions: Sequence[str] = ()


_PROVIDERS: MutableMapping[str, FederationProvider] = {}


def register_provider(provider: FederationProvider) -> None:
    """Register a new SSO federation provider."""

    key = provider.slug.strip().lower()
    if not key:
        raise ValueError("Provider slug must not be empty")
    _PROVIDERS[key] = provider
    logger.info("Registered federation provider %s", provider.slug)


def get_provider(slug: str) -> FederationProvider:
    normalized = slug.strip().lower()
    try:
        return _PROVIDERS[normalized]
    except KeyError as exc:  # pragma: no cover - defensive
        raise LookupError(f"Federation provider '{slug}' is not configured") from exc


def list_providers() -> Sequence[FederationProvider]:
    """Return the configured SSO providers."""

    return tuple(_PROVIDERS.values())


def _resolve_role(provider: FederationProvider, claims: Mapping[str, object]) -> str:
    requested = str(claims.get(provider.role_claim, "") or "").strip().lower()
    if requested and requested in provider.role_mapping:
        return provider.role_mapping[requested]
    return provider.default_role


def _health_check(provider: FederationProvider, claims: Mapping[str, object]) -> None:
    if provider.health_check and not provider.health_check(claims):
        raise ValueError(f"Federation assertion for {provider.slug} failed health verification")


def federated_login(provider_slug: str, claims: Mapping[str, object], *, session: Session) -> FederationResult:
    """Process a federated assertion and ensure the admin exists locally."""

    provider = get_provider(provider_slug)
    issuer = str(claims.get("iss", ""))
    audience = str(claims.get("aud", ""))
    email = str(claims.get(provider.email_claim, "") or "").strip().lower()
    subject = str(claims.get("sub", "") or "").strip()

    if not issuer or issuer != provider.issuer:
        raise ValueError("Federation issuer mismatch")
    if audience and audience != provider.audience:
        raise ValueError("Federation audience mismatch")
    if not email:
        raise ValueError("Federation assertion missing email claim")
    if not subject:
        raise ValueError("Federation assertion missing subject identifier")

    _health_check(provider, claims)

    admin = session.exec(
        select(AdminUser).where(
            (AdminUser.external_id == subject) | (AdminUser.email == email)
        )
    ).first()
    created = False

    if admin is None:
        try:
            password = _generate_placeholder_password("rotated")
            admin = ensure_admin(
                session,
                email=email,
                password=password,
                role=provider.default_role,
            )
        except AdminAlreadyExistsError:
            admin = session.exec(select(AdminUser).where(AdminUser.email == email)).one()
        created = True

    admin.external_id = subject
    providers = set(admin.federated_providers or [])
    providers.add(provider.slug)
    admin.federated_providers = sorted(providers)
    session.add(admin)
    session.commit()
    session.refresh(admin)

    resolved_role = _resolve_role(provider, claims)
    assign_role(session, admin_id=admin.id, role=resolved_role)

    record_admin_event(
        "sso.login",
        actor=email,
        ip_address=None,
        metadata={"provider": provider.slug, "created": created},
        session=session,
    )
    return FederationResult(admin=admin, provider=provider.slug, created=created)


def apply_scim_event(event: SCIMEvent, *, session: Session) -> AdminUser:
    """Apply the provisioning delta to the admin roster."""

    admin = session.exec(
        select(AdminUser).where(
            (AdminUser.external_id == event.identifier) | (AdminUser.email == event.email.lower())
        )
    ).first()

    if admin is None:
        password = _generate_placeholder_password("provisioned")
        admin = ensure_admin(
            session,
            email=event.email,
            password=password,
            role=event.role,
        )
        admin.external_id = event.identifier
        session.add(admin)
        session.commit()
        session.refresh(admin)
        created = True
    else:
        created = False

    admin.is_active = bool(event.active)
    admin.updated_at = datetime.now(tz=UTC)
    session.add(admin)
    session.commit()
    session.refresh(admin)

    assign_role(session, admin_id=admin.id, role=event.role, extra_permissions=event.permissions)

    record_admin_event(
        "scim.provision" if created else "scim.update",
        actor="scim",
        ip_address=None,
        metadata={
            "identifier": event.identifier,
            "active": event.active,
            "role": event.role,
            "permissions": list(event.permissions or []),
        },
        session=session,
    )
    return admin


def verify_hardware_assertion(admin: AdminUser, assertion: str | None) -> bool:
    """Return ``True`` when the supplied hardware assertion matches enrolment."""

    enrolled = [fingerprint.strip().lower() for fingerprint in admin.hardware_key_fingerprints or [] if fingerprint]
    if not enrolled:
        return True
    if not assertion:
        return False
    return assertion.strip().lower() in enrolled


def enroll_hardware_key(admin: AdminUser, fingerprint: str, *, session: Session) -> AdminUser:
    """Persist a new hardware key fingerprint for the admin."""

    normalized = fingerprint.strip().lower()
    if not normalized:
        raise ValueError("Fingerprint must not be empty")

    keys = set(admin.hardware_key_fingerprints or [])
    keys.add(normalized)
    admin.hardware_key_fingerprints = sorted(keys)
    admin.updated_at = datetime.now(tz=UTC)
    session.add(admin)
    session.commit()
    session.refresh(admin)

    record_admin_event(
        "hardware.enroll",
        actor=admin.email,
        ip_address=None,
        metadata={"fingerprint": normalized},
        session=session,
    )
    return admin


__all__ = [
    "FederationProvider",
    "FederationResult",
    "SCIMEvent",
    "apply_scim_event",
    "enroll_hardware_key",
    "federated_login",
    "get_provider",
    "list_providers",
    "register_provider",
    "verify_hardware_assertion",
]

