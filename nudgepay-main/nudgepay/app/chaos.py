"""Chaos engineering utilities for external integrations."""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, List


@dataclass(frozen=True)
class ChaosResult:
    name: str
    succeeded: bool
    error: str | None = None


def _run_probe(name: str, probe: Callable[[], None]) -> ChaosResult:
    try:
        probe()
    except Exception as exc:  # pragma: no cover - surfaced to result for assertions
        return ChaosResult(name=name, succeeded=False, error=str(exc))
    return ChaosResult(name=name, succeeded=True, error=None)


def run_experiments(
    experiments: Iterable[tuple[str, Callable[[], None]]]
) -> List[ChaosResult]:
    """Execute chaos probes and capture their outcomes."""

    return [_run_probe(name, probe) for name, probe in experiments]


@contextlib.contextmanager
def simulate_smtp_outage() -> Iterator[None]:
    """Temporarily force the SMTP emailer to raise connection errors."""

    from . import emailer

    original = emailer.send_email

    def _raise(*_args, **_kwargs):  # pragma: no cover - deterministic raise
        raise ConnectionError("SMTP outage simulated")

    emailer.send_email = _raise
    try:
        yield
    finally:
        emailer.send_email = original


@contextlib.contextmanager
def simulate_stripe_outage() -> Iterator[None]:
    """Force Stripe webhook verification to fail."""

    from . import payments

    original = payments.verify_webhook

    def _raise(*_args, **_kwargs):  # pragma: no cover - deterministic raise
        raise ConnectionError("Stripe outage simulated")

    payments.verify_webhook = _raise
    try:
        yield
    finally:
        payments.verify_webhook = original


@contextlib.contextmanager
def simulate_webhook_replay(event_id: str = "evt_replay") -> Iterator[None]:
    """Replay a webhook event identifier to exercise idempotency."""

    from . import payments

    original = payments.verify_webhook

    def _wrap(
        sig: str | None, payload: bytes
    ):  # pragma: no cover - deterministic patch
        event = original(sig, payload)
        event["id"] = event_id
        return event

    payments.verify_webhook = _wrap
    try:
        yield
    finally:
        payments.verify_webhook = original


@contextlib.contextmanager
def simulate_webhook_backoff(failures: int = 2) -> Iterator[None]:
    """Inject webhook verification failures before succeeding."""

    from . import payments

    original = payments.verify_webhook
    counter = {"remaining": max(0, failures)}

    def _wrap(
        sig: str | None, payload: bytes
    ):  # pragma: no cover - deterministic patch
        if counter["remaining"] > 0:
            counter["remaining"] -= 1
            raise TimeoutError("Simulated webhook backoff")
        return original(sig, payload)

    payments.verify_webhook = _wrap
    try:
        yield
    finally:
        payments.verify_webhook = original


@contextlib.contextmanager
def simulate_dependency_degradation(
    provider: str,
    *,
    failures: int = 1,
    latency_seconds: float = 0.25,
) -> Iterator[None]:
    """Inject upstream dependency latency/failures."""

    if provider == "stripe-payments":
        from . import payments

        original = payments.ensure_payment_link
        counter = {"remaining": max(0, failures)}

        def _wrap(
            amount_cents: int,
            currency: str,
            invoice_number: str,
            metadata: dict[str, str],
        ) -> str:  # pragma: no cover - deterministic patch
            if counter["remaining"] > 0:
                counter["remaining"] -= 1
                raise TimeoutError("Simulated Stripe payment link degradation")
            if latency_seconds:
                time.sleep(latency_seconds)
            return f"https://fallback.nudgepay.test/{invoice_number}"

        payments.ensure_payment_link = _wrap
        try:
            yield
        finally:
            payments.ensure_payment_link = original
        return

    if provider == "stripe-webhook":
        from . import payments

        original = payments.verify_webhook
        counter = {"remaining": max(0, failures)}

        def _wrap(
            sig_header: str | None, payload: bytes
        ):  # pragma: no cover - deterministic patch
            if counter["remaining"] > 0:
                counter["remaining"] -= 1
                raise TimeoutError("Simulated Stripe webhook degradation")
            if latency_seconds:
                time.sleep(latency_seconds)
            return {
                "id": "evt_degraded",
                "type": "payment_intent.succeeded",
                "payload": payload.decode("utf-8", "ignore"),
            }

        payments.verify_webhook = _wrap
        try:
            yield
        finally:
            payments.verify_webhook = original
        return

    raise ValueError(f"Unknown provider for degradation: {provider}")


def build_dependency_game_day() -> list[tuple[str, Callable[[], None]]]:
    """Return chaos probes that exercise upstream degradation scenarios."""

    def _smtp_probe() -> None:
        from . import emailer

        with simulate_smtp_outage():
            try:
                emailer.send_email("ops@nudgepay.test", "Chaos drill", "body")
            except ConnectionError:
                pass

    def _stripe_outage_probe() -> None:
        from . import payments

        with simulate_stripe_outage():
            try:
                payments.verify_webhook("sig", b"{}")
            except ConnectionError:
                pass

    def _stripe_backoff_probe() -> None:
        from . import payments

        with simulate_webhook_backoff(failures=2):
            failures = 0
            for _ in range(3):
                try:
                    payments.verify_webhook("sig", b"{}")
                except TimeoutError:
                    failures += 1
            if failures < 2:
                raise AssertionError("Expected webhook backoff to trigger failures")

    def _stripe_degradation_probe() -> None:
        from . import payments

        with simulate_dependency_degradation(
            "stripe-payments", failures=1, latency_seconds=0.1
        ):
            try:
                payments.ensure_payment_link(
                    1000, "usd", "CHAOS-1", {"invoice_id": "CHAOS-1"}
                )
            except TimeoutError:
                pass
            url = payments.ensure_payment_link(
                1000, "usd", "CHAOS-1", {"invoice_id": "CHAOS-1"}
            )
            if "fallback" not in url:
                raise AssertionError("Fallback URL not used during degradation probe")

    def _webhook_degradation_probe() -> None:
        from . import payments

        with simulate_dependency_degradation(
            "stripe-webhook", failures=1, latency_seconds=0.1
        ):
            try:
                payments.verify_webhook("sig", b"{}")
            except TimeoutError:
                pass
            event = payments.verify_webhook("sig", b"{}")
            if event.get("id") != "evt_degraded":
                raise AssertionError("Degraded webhook event not returned")

    return [
        ("smtp_outage", _smtp_probe),
        ("stripe_outage", _stripe_outage_probe),
        ("stripe_webhook_backoff", _stripe_backoff_probe),
        ("stripe_payment_degradation", _stripe_degradation_probe),
        ("stripe_webhook_degradation", _webhook_degradation_probe),
    ]


__all__ = [
    "ChaosResult",
    "run_experiments",
    "simulate_smtp_outage",
    "simulate_stripe_outage",
    "simulate_webhook_replay",
    "simulate_webhook_backoff",
    "simulate_dependency_degradation",
    "build_dependency_game_day",
]
