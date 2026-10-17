import sys
import types
from types import SimpleNamespace

import pytest

from app import secret_manager


@pytest.fixture(autouse=True)
def clear_cache():
    secret_manager.resolve_managed_secret.cache_clear()
    yield
    secret_manager.resolve_managed_secret.cache_clear()


def test_resolve_vault_secret(monkeypatch):
    class FakeClient:
        def __init__(self, url: str, token: str) -> None:
            self.url = url
            self.token = token
            self.secrets = SimpleNamespace(
                kv=SimpleNamespace(
                    v2=SimpleNamespace(
                        read_secret_version=lambda path: {
                            "data": {
                                "data": {"password": "s3cr3t"},
                                "metadata": {"version": 7},
                            }
                        }
                    )
                )
            )

    fake_module = types.ModuleType("hvac")
    exceptions_mod = types.ModuleType("hvac.exceptions")
    exceptions_mod.InvalidPath = KeyError
    fake_module.Client = FakeClient
    fake_module.exceptions = exceptions_mod
    monkeypatch.setitem(sys.modules, "hvac", fake_module)
    monkeypatch.setitem(sys.modules, "hvac.exceptions", exceptions_mod)
    monkeypatch.setenv("VAULT_ADDR", "https://vault")
    monkeypatch.setenv("VAULT_TOKEN", "token123")

    secret = secret_manager.resolve_managed_secret("vault://secret/data/app#password")
    assert secret.value == "s3cr3t"
    assert secret.metadata["version"] == "7"


def test_resolve_gcp_secret_supports_latest_version(monkeypatch):
    class FakeResponse:
        def __init__(self) -> None:
            self.payload = SimpleNamespace(data=b"{\"token\": \"abc\"}")

    class FakeClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def access_secret_version(self, name: str):
            self.calls.append(name)
            resp = FakeResponse()
            resp.name = name
            return resp

    google_mod = types.ModuleType("google")
    cloud_mod = types.ModuleType("google.cloud")
    secret_mod = types.ModuleType("google.cloud.secretmanager")
    secret_mod.SecretManagerServiceClient = FakeClient
    cloud_mod.secretmanager = secret_mod
    google_mod.cloud = cloud_mod
    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", secret_mod)

    secret = secret_manager.resolve_managed_secret(
        "gcp-sm://projects/demo/secrets/api-token#token"
    )
    assert secret.value == "abc"
    assert "versions/latest" in secret.metadata["name"]
