"""Managed secret rotation utilities with policy orchestration."""

from __future__ import annotations

import fnmatch
import json
import logging
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Sequence

from . import cache_invalidation
from .config import Settings, get_settings
from .http_utils import safe_urlopen
from .secret_manager import (
    ManagedSecret,
    SecretResolutionError,
    SecretUpdateError,
    resolve_managed_secret,
    update_managed_secret,
)
from .tasks import enqueue_secret_invalidation

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RolloutStage:
    name: str
    warm_up_seconds: int | None = None
    queue_targets: tuple[str, ...] = ()


@dataclass(slots=True)
class RotationPolicy:
    name: str
    warm_up_seconds: int = 60
    stages: tuple[RolloutStage, ...] = ()
    queues: tuple[str, ...] = ()
    health_check: Callable[[ManagedSecret], bool] | None = None


@dataclass(slots=True)
class RotationResult:
    reference: str
    managed_secret: ManagedSecret
    policy_name: str
    pattern: str
    hook_count: int = 0
    stages: tuple[str, ...] = ()
    name: str | None = None
    stage_definitions: tuple[RolloutStage, ...] = field(default_factory=tuple, repr=False)
    policy: RotationPolicy = field(
        default_factory=lambda: RotationPolicy(name="default"),
        repr=False,
    )

    @property
    def metadata(self) -> Mapping[str, str]:
        return dict(self.managed_secret.metadata)


Generator = Callable[[], str]
Hook = Callable[[str, ManagedSecret], None]


_POLICY_REGISTRY: dict[str, RotationPolicy] = {
    "*": RotationPolicy(name="default"),
}


def register_rotation_policy(pattern: str, policy: RotationPolicy) -> None:
    """Register or replace a rotation policy for matching references."""

    _POLICY_REGISTRY[pattern] = policy
    logger.info("Registered rotation policy '%s' for pattern '%s'", policy.name, pattern)


def _match_policy(reference: str) -> tuple[str, RotationPolicy]:
    if "*" not in _POLICY_REGISTRY:
        _POLICY_REGISTRY["*"] = RotationPolicy(name="default")
    for pattern, policy in sorted(
        _POLICY_REGISTRY.items(), key=lambda item: (-len(item[0]), item[0])
    ):
        if fnmatch.fnmatch(reference, pattern):
            return pattern, policy
    return "*", _POLICY_REGISTRY["*"]


def _stage_definitions(policy: RotationPolicy) -> tuple[RolloutStage, ...]:
    if policy.stages:
        return policy.stages
    return (
        RolloutStage(
            name=policy.name,
            warm_up_seconds=policy.warm_up_seconds,
            queue_targets=policy.queues,
        ),
    )


def _call_hook(url: str, reference: str, secret: ManagedSecret) -> None:
    payload = json.dumps(
        {
            "reference": reference,
            "metadata": dict(secret.metadata),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with safe_urlopen(request, timeout=5) as response:  # pragma: no cover - network
            response.read()
    except urllib.error.URLError as exc:  # pragma: no cover - network
        logger.warning("Secret rotation hook %s failed: %s", url, exc)


def rotate_secret(
    reference: str,
    *,
    rotator: Callable[[str], ManagedSecret],
    hooks: Iterable[Hook] | None = None,
) -> RotationResult:
    """Rotate a managed secret reference and run the supplied hooks."""

    if not reference:
        raise RuntimeError("Secret reference must be provided")

    current = resolve_managed_secret(reference)
    candidate = rotator(reference)
    if not isinstance(candidate, ManagedSecret):
        raise RuntimeError("Rotator must return a ManagedSecret instance")
    new_value = candidate.value.strip()
    if not new_value:
        raise RuntimeError("Generated secret must not be empty")
    if new_value == current.value:
        raise RuntimeError("Rotated secret matches the existing value")

    update_managed_secret(reference, new_value)
    try:
        refreshed = resolve_managed_secret(reference)
    except SecretResolutionError as exc:
        raise SecretUpdateError(f"Failed to resolve rotated secret {reference}: {exc}") from exc
    if refreshed is current:
        logger.debug(
            "Resolver returned cached secret for %s; skipping value verification", reference
        )
    elif refreshed.value != new_value:
        raise SecretUpdateError(
            f"Secret {reference} did not resolve to the newly rotated value"
        )

    hook_list = list(hooks or [])
    for hook in hook_list:
        hook(reference, candidate)

    pattern, policy = _match_policy(reference)
    stages = _stage_definitions(policy)
    result = RotationResult(
        reference=reference,
        managed_secret=candidate,
        policy_name=policy.name,
        pattern=pattern,
        hook_count=len(hook_list),
        stages=tuple(stage.name for stage in stages),
        stage_definitions=stages,
        policy=policy,
    )
    return result


def schedule_rotations(
    references: Sequence[str],
    *,
    rotator: Callable[[str], ManagedSecret],
    hooks: Iterable[Hook] | None = None,
) -> list[RotationResult]:
    """Rotate the provided secrets, invoke hooks, and enqueue cache invalidation."""

    settings = get_settings()
    configured_hooks = tuple(getattr(settings, "secret_rotation_hook_urls", ()))
    grace_seconds = int(getattr(settings, "secret_rotation_grace_seconds", 0) or 0)
    results: list[RotationResult] = []

    for reference in references:
        result = rotate_secret(reference, rotator=rotator, hooks=hooks)

        if result.policy.health_check and not result.policy.health_check(result.managed_secret):
            raise RuntimeError(f"Secret rotation health check failed for {reference}")

        for url in configured_hooks:
            _call_hook(url, reference, result.managed_secret)
            result.hook_count += 1

        metadata = {
            **result.metadata,
            "policy": result.policy_name,
            "pattern": result.pattern,
            "warm_up_seconds": str(result.policy.warm_up_seconds),
        }
        cache_invalidation.notify_secret_rotation(reference, metadata)

        for stage in result.stage_definitions:
            warm_up = (
                stage.warm_up_seconds
                if stage.warm_up_seconds is not None
                else result.policy.warm_up_seconds
            )
            enqueue_secret_invalidation(
                reference,
                metadata={
                    "policy": result.policy_name,
                    "stage": stage.name,
                    "grace_seconds": str(grace_seconds),
                },
                stage=stage.name,
                warm_up_seconds=warm_up,
                queues=stage.queue_targets,
            )
        results.append(result)

    return results


def _default_generator(size: int = 48) -> str:
    return secrets.token_urlsafe(size)


def rotate_core_application_secrets(
    settings: Settings, *, generator: Generator | None = None
) -> list[RotationResult]:
    """Rotate critical application secrets tracked in settings."""

    generator = generator or (lambda: _default_generator())
    spec_map: Mapping[str, str | None] = {
        "session_secret": settings.session_secret_ref,
        "cron_secret": settings.cron_secret_ref,
        "cron_hmac_secret": settings.cron_hmac_secret_ref,
        "service_token_pepper": settings.service_token_pepper_ref,
        "admin_password_hash": settings.admin_password_hash_ref,
        "admin_totp_secret": settings.admin_totp_secret_ref,
    }
    results: list[RotationResult] = []
    for name, reference in spec_map.items():
        if not reference:
            raise SecretUpdateError(
                f"Managed secret reference not configured for {name}"
            )
        outcome = rotate_secret(
            reference,
            rotator=lambda spec, gen=generator: ManagedSecret(
                value=gen(), metadata={}
            ),
        )
        outcome.name = name
        results.append(outcome)
    return results


__all__ = [
    "RolloutStage",
    "RotationPolicy",
    "RotationResult",
    "register_rotation_policy",
    "rotate_secret",
    "schedule_rotations",
    "rotate_core_application_secrets",
]
