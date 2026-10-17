from types import SimpleNamespace

import pytest

from app import secret_rotation
from app.secret_manager import ManagedSecret


class DummyResolver:
    def __init__(self, secret: ManagedSecret):
        self.secret = secret
        self.calls = 0

    def __call__(self, spec: str) -> ManagedSecret:
        self.calls += 1
        return self.secret

    def cache_clear(self) -> None:
        self.calls = 0


@pytest.fixture(autouse=True)
def reset_policies(monkeypatch):
    registry: dict[str, secret_rotation.RotationPolicy] = {}
    monkeypatch.setattr(secret_rotation, "_POLICY_REGISTRY", registry, raising=False)
    yield


def test_rotate_secret_invokes_hooks(monkeypatch):
    old_secret = ManagedSecret(value="old", metadata={"version": "1"})
    new_secret = ManagedSecret(value="new", metadata={"version": "2"})
    resolver = DummyResolver(old_secret)
    monkeypatch.setattr(secret_rotation, "resolve_managed_secret", resolver)

    hook_calls: list[tuple[str, ManagedSecret]] = []

    result = secret_rotation.rotate_secret(
        "aws-secrets://prod/api",
        rotator=lambda spec: new_secret,
        hooks=[lambda spec, secret: hook_calls.append((spec, secret))],
    )

    assert result.metadata == {"version": "2"}
    assert result.hook_count == 1
    assert result.policy_name == "default"
    assert hook_calls == [("aws-secrets://prod/api", new_secret)]


def test_schedule_rotations_uses_configured_hooks(monkeypatch):
    old_secret = ManagedSecret(value="old", metadata={})
    new_secret = ManagedSecret(value="new", metadata={})
    resolver = DummyResolver(old_secret)
    monkeypatch.setattr(secret_rotation, "resolve_managed_secret", resolver)

    settings = SimpleNamespace(
        secret_rotation_hook_urls=("https://hooks.example",),
        secret_rotation_grace_seconds=60,
    )
    monkeypatch.setattr(secret_rotation, "get_settings", lambda: settings)

    invoked: list[tuple[str, ManagedSecret]] = []
    monkeypatch.setattr(secret_rotation, "_call_hook", lambda url, spec, secret: invoked.append((url, spec)))

    def fake_enqueue(spec: str, metadata, *, stage: str, warm_up_seconds: int, queues):
        enqueue_calls.append((stage, warm_up_seconds, queues, metadata["policy"]))

    enqueue_calls: list[tuple[str, int, tuple[str, ...], str]] = []
    monkeypatch.setattr(secret_rotation, "enqueue_secret_invalidation", fake_enqueue)

    secret_rotation.register_rotation_policy(
        "aws-secrets://prod/*",
        secret_rotation.RotationPolicy(
            name="prod",
            warm_up_seconds=120,
            stages=(
                secret_rotation.RolloutStage(name="workers", queue_targets=("worker",)),
                secret_rotation.RolloutStage(name="api", warm_up_seconds=300, queue_targets=("api",)),
            ),
        ),
    )

    results = secret_rotation.schedule_rotations(["aws-secrets://prod/api"], rotator=lambda spec: new_secret)

    assert results[0].hook_count == 1
    assert results[0].policy_name == "prod"
    assert results[0].stages == ("workers", "api")
    assert invoked == [("https://hooks.example", "aws-secrets://prod/api")]
    assert enqueue_calls == [
        ("workers", 120, ("worker",), "prod"),
        ("api", 300, ("api",), "prod"),
    ]


def test_schedule_rotations_enriches_cache_invalidation(monkeypatch):
    old_secret = ManagedSecret(value="old", metadata={})
    new_secret = ManagedSecret(value="new", metadata={"version": "2"})
    resolver = DummyResolver(old_secret)
    monkeypatch.setattr(secret_rotation, "resolve_managed_secret", resolver)

    settings = SimpleNamespace(secret_rotation_hook_urls=(), secret_rotation_grace_seconds=60)
    monkeypatch.setattr(secret_rotation, "get_settings", lambda: settings)

    secret_rotation.register_rotation_policy(
        "*",
        secret_rotation.RotationPolicy(name="default", warm_up_seconds=42),
    )

    calls: list[tuple[str, dict[str, str]]] = []
    monkeypatch.setattr(
        secret_rotation.cache_invalidation,
        "notify_secret_rotation",
        lambda spec, metadata: calls.append((spec, metadata)),
    )
    monkeypatch.setattr(secret_rotation, "enqueue_secret_invalidation", lambda *args, **kwargs: None)

    secret_rotation.schedule_rotations(["vault://prod/api"], rotator=lambda spec: new_secret)

    assert calls == [
        (
            "vault://prod/api",
            {"version": "2", "policy": "default", "pattern": "*", "warm_up_seconds": "42"},
        )
    ]


def test_rotate_secret_requires_new_value(monkeypatch):
    secret = ManagedSecret(value="same", metadata={})
    resolver = DummyResolver(secret)
    monkeypatch.setattr(secret_rotation, "resolve_managed_secret", resolver)

    with pytest.raises(RuntimeError):
        secret_rotation.rotate_secret("aws-secrets://prod/api", rotator=lambda spec: secret)


def test_rotate_secret_health_check_failure(monkeypatch):
    old_secret = ManagedSecret(value="old", metadata={})
    new_secret = ManagedSecret(value="new", metadata={})
    resolver = DummyResolver(old_secret)
    monkeypatch.setattr(secret_rotation, "resolve_managed_secret", resolver)

    secret_rotation.register_rotation_policy(
        "aws-secrets://prod/*",
        secret_rotation.RotationPolicy(name="prod", warm_up_seconds=10, health_check=lambda secret: False),
    )

    with pytest.raises(RuntimeError):
        secret_rotation.schedule_rotations(["aws-secrets://prod/api"], rotator=lambda spec: new_secret)
