"""Stripe payment integration helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List

import stripe

try:  # pragma: no cover - optional dependency handling
    from tenacity import retry, stop_after_attempt, wait_exponential
except ImportError:  # pragma: no cover - lightweight fallback
    from functools import wraps

    def retry(*_args, **_kwargs):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def stop_after_attempt(_attempts: int):  # type: ignore[override]
        return None

    def wait_exponential(**_kwargs):  # type: ignore[override]
        return None

from .config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()
stripe.api_key = settings.stripe_secret_key


@dataclass(slots=True)
class WebhookSecretState:
    """Represents the lifecycle of a webhook signing secret."""

    value: str
    activates_at: datetime
    retires_at: datetime | None = None

    def is_active(self, now: datetime) -> bool:
        if self.activates_at > now:
            return False
        if self.retires_at and self.retires_at <= now:
            return False
        return True


class WebhookSecretManager:
    """Automate webhook secret rotation with overlap handling."""

    def __init__(self, rotation_days: int, overlap_seconds: int) -> None:
        self.rotation_days = rotation_days
        self.overlap_seconds = overlap_seconds
        self._secrets: list[WebhookSecretState] = []
        self._last_rotated_at: datetime | None = None

    def configure(self, primary: str, additional: Iterable[str]) -> None:
        now = datetime.now(tz=UTC)
        secrets: list[WebhookSecretState] = []
        if primary:
            secrets.append(WebhookSecretState(value=primary, activates_at=now))
        for index, secret in enumerate(additional):
            if not secret:
                continue
            activated = now - timedelta(seconds=self.overlap_seconds * (index + 1))
            secrets.append(WebhookSecretState(value=secret, activates_at=activated))
        self._secrets = sorted(secrets, key=lambda state: state.activates_at, reverse=True)
        self._last_rotated_at = now if secrets else None

    def active_secrets(self, now: datetime | None = None) -> list[str]:
        now = now or datetime.now(tz=UTC)
        self._prune(now)
        return [state.value for state in self._secrets if state.is_active(now)]

    def rotate(self, generator: Callable[[], str], now: datetime | None = None) -> WebhookSecretState:
        now = now or datetime.now(tz=UTC)
        new_secret = generator().strip()
        if not new_secret:
            raise ValueError("Generated webhook secret must not be empty")
        for state in self._secrets:
            if state.is_active(now):
                state.retires_at = now + timedelta(seconds=self.overlap_seconds)
        record = WebhookSecretState(value=new_secret, activates_at=now)
        self._secrets.append(record)
        self._secrets.sort(key=lambda state: state.activates_at, reverse=True)
        self._last_rotated_at = now
        return record

    def retire(self, secret: str, now: datetime | None = None) -> None:
        now = now or datetime.now(tz=UTC)
        for state in self._secrets:
            if state.value == secret:
                state.retires_at = now
                break
        self._prune(now)

    def purge_expired(self, now: datetime | None = None) -> int:
        """Remove secrets past their retirement window."""

        return self._prune(now)

    def _prune(self, now: datetime | None = None) -> int:
        now = now or datetime.now(tz=UTC)
        before = len(self._secrets)
        self._secrets = [state for state in self._secrets if state.retires_at is None or state.retires_at > now]
        return before - len(self._secrets)

    def schedule(self, now: datetime | None = None) -> datetime:
        now = now or datetime.now(tz=UTC)
        baseline = self._last_rotated_at or now
        return baseline + timedelta(days=self.rotation_days)


_webhook_secrets = WebhookSecretManager(
    rotation_days=settings.webhook_secret_rotation_days,
    overlap_seconds=settings.webhook_secret_overlap_seconds,
)
_webhook_secrets.configure(settings.stripe_webhook_secret, settings.stripe_webhook_additional_secrets)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=60), reraise=True)
def _create_payment_link(amount_cents: int, currency: str, product_name: str, metadata: Dict[str, str]) -> str:
    price = stripe.Price.create(
        currency=currency,
        unit_amount=amount_cents,
        product_data={"name": product_name},
        idempotency_key=f"price_{metadata.get('invoice_id', product_name)}",
    )
    link = stripe.PaymentLink.create(
        line_items=[{"price": price.id, "quantity": 1}],
        metadata=metadata,
        idempotency_key=f"payment_link_{metadata.get('invoice_id', product_name)}",
    )
    return link.url


def ensure_payment_link(amount_cents: int, currency: str, invoice_number: str, metadata: Dict[str, str]) -> str:
    """Create and return a Stripe payment link URL for the invoice."""

    product_name = f"{settings.stripe_product_name} #{invoice_number}".strip()
    try:
        url = _create_payment_link(amount_cents, currency, product_name, metadata)
    except Exception:  # pragma: no cover - depends on Stripe API
        logger.exception("Failed to create Stripe payment link for invoice %s", invoice_number)
        raise

    logger.info("Stripe payment link created for invoice %s", invoice_number)
    return url


def verify_webhook(sig_header: str | None, payload: bytes) -> Dict[str, Any]:
    """Verify a Stripe webhook payload."""

    if not sig_header:
        raise ValueError("Missing Stripe signature header")

    secrets = _webhook_secrets.active_secrets()
    errors: list[Exception] = []
    for secret in secrets:
        if not secret:
            continue
        try:
            return stripe.Webhook.construct_event(payload, sig_header, secret)
        except Exception as exc:  # pragma: no cover - dependent on Stripe library
            errors.append(exc)
    if errors:
        raise errors[-1]
    raise ValueError("No Stripe webhook secrets configured")


def rotate_webhook_secret(generator: Callable[[], str]) -> WebhookSecretState:
    """Rotate the webhook secret and return the pending state."""

    return _webhook_secrets.rotate(generator)


def retire_webhook_secret(secret: str) -> None:
    """Retire a webhook secret immediately."""

    _webhook_secrets.retire(secret)


def purge_expired_webhook_secrets(now: datetime | None = None) -> int:
    """Drop webhook secrets that have passed their overlap period."""

    return _webhook_secrets.purge_expired(now)


def next_webhook_rotation(now: datetime | None = None) -> datetime:
    """Return when the next webhook rotation should occur."""

    return _webhook_secrets.schedule(now)


def active_webhook_secrets() -> List[str]:
    """Expose the currently active webhook secrets."""

    return _webhook_secrets.active_secrets()


__all__ = [
    "WebhookSecretManager",
    "WebhookSecretState",
    "active_webhook_secrets",
    "purge_expired_webhook_secrets",
    "ensure_payment_link",
    "next_webhook_rotation",
    "retire_webhook_secret",
    "rotate_webhook_secret",
    "verify_webhook",
]
