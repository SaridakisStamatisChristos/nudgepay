"""Helpers for fetching managed secrets from external providers."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Dict

logger = logging.getLogger(__name__)

_FALLBACK_MARKER = "__value__"
_FALLBACK_STORE: dict[str, dict[str, dict[str, str]]] = {}


def _fallback_enabled() -> bool:
    return bool(
        os.getenv("NUDGPAY_SECRET_STORE_FALLBACKS")
        or os.getenv("PYTEST_CURRENT_TEST")
    )


def _fallback_key(key: str | None) -> str:
    return key or _FALLBACK_MARKER


def _store_fallback_secret(
    provider: str, identifier: str, value: str, *, key: str | None = None
) -> ManagedSecret:
    entry = _FALLBACK_STORE.setdefault(provider, {}).setdefault(identifier, {})
    entry[_fallback_key(key)] = value
    metadata = {"provider": provider, "name": identifier, "mode": "fallback"}
    if key:
        metadata["key"] = key
    logger.debug("Stored fallback secret for %s://%s", provider, identifier)
    return ManagedSecret(value=value, metadata=metadata)


def _load_fallback_secret(
    provider: str, identifier: str, *, key: str | None = None
) -> ManagedSecret:
    provider_store = _FALLBACK_STORE.get(provider, {})
    entry = provider_store.get(identifier)
    if not entry:
        raise SecretResolutionError(
            f"Fallback secret '{provider}://{identifier}' not initialized"
        )
    fallback_key = _fallback_key(key)
    if fallback_key not in entry:
        raise SecretResolutionError(
            f"Fallback secret '{provider}://{identifier}' missing key '{key}'"
        )
    metadata = {"provider": provider, "name": identifier, "mode": "fallback"}
    if key:
        metadata["key"] = key
    return ManagedSecret(value=entry[fallback_key], metadata=metadata)


class SecretResolutionError(RuntimeError):
    """Raised when a managed secret cannot be resolved."""


class SecretUpdateError(RuntimeError):
    """Raised when a managed secret cannot be updated."""


@dataclass(frozen=True)
class ManagedSecret:
    """Structured response for resolved secrets."""

    value: str
    metadata: Dict[str, str]


def _load_aws_secret(secret_id: str, *, key: str | None = None) -> ManagedSecret:
    if _fallback_enabled():
        try:
            return _load_fallback_secret("aws-secrets", secret_id, key=key)
        except SecretResolutionError:
            pass
    try:  # pragma: no cover - requires boto3 dependency and credentials
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SecretResolutionError(
            "boto3 is required for AWS Secrets Manager integration"
        ) from exc

    client = boto3.client("secretsmanager")
    try:
        result = client.get_secret_value(SecretId=secret_id)
    except (BotoCoreError, ClientError) as exc:  # pragma: no cover - AWS interaction
        raise SecretResolutionError(
            f"Failed to fetch secret {secret_id}: {exc}"
        ) from exc

    if "SecretString" in result:
        payload = result["SecretString"]
    else:  # pragma: no cover - binary secrets are rare
        payload = result.get("SecretBinary", b"").decode("utf-8")

    metadata = {"arn": result.get("ARN", ""), "name": result.get("Name", secret_id)}
    if key:
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - depends on remote data
            raise SecretResolutionError(
                f"Secret {secret_id} is not JSON but key '{key}' was requested"
            ) from exc
        if key not in document:
            raise SecretResolutionError(f"Key '{key}' not found in secret {secret_id}")
        value = str(document[key])
    else:
        value = payload

    return ManagedSecret(value=value, metadata=metadata)


def _load_vault_secret(secret_path: str, key: str | None = None) -> ManagedSecret:
    if _fallback_enabled():
        try:
            return _load_fallback_secret("vault", secret_path, key=key)
        except SecretResolutionError:
            pass
    try:  # pragma: no cover - optional dependency
        import hvac  # type: ignore
        from hvac.exceptions import InvalidPath  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SecretResolutionError("hvac is required for Vault integration") from exc

    addr = os.getenv("VAULT_ADDR")
    token = os.getenv("VAULT_TOKEN")
    if not addr or not token:
        raise SecretResolutionError(
            "VAULT_ADDR and VAULT_TOKEN must be set for Vault secrets"
        )

    client = hvac.Client(url=addr, token=token)
    try:
        response = client.secrets.kv.v2.read_secret_version(path=secret_path)
    except InvalidPath as exc:  # pragma: no cover - depends on remote data
        raise SecretResolutionError(f"Vault secret '{secret_path}' not found") from exc
    except Exception as exc:  # pragma: no cover - remote dependency
        raise SecretResolutionError(
            f"Failed reading Vault secret '{secret_path}': {exc}"
        ) from exc

    data = (response.get("data") or {}).get("data") or {}
    metadata = (response.get("data") or {}).get("metadata") or {}
    metadata_out = {
        "path": secret_path,
        "version": str(metadata.get("version", "")),
    }

    if key:
        if key not in data:
            raise SecretResolutionError(
                f"Key '{key}' not found in Vault secret {secret_path}"
            )
        value = str(data[key])
    else:
        if len(data) == 1:
            value = str(next(iter(data.values())))
        else:
            raise SecretResolutionError(
                f"Vault secret {secret_path} contains multiple keys; specify one explicitly"
            )

    return ManagedSecret(value=value, metadata=metadata_out)


def _load_gcp_secret(resource: str, key: str | None = None) -> ManagedSecret:
    if _fallback_enabled():
        try:
            return _load_fallback_secret("gcp-sm", resource, key=key)
        except SecretResolutionError:
            pass
    try:  # pragma: no cover - optional dependency
        from google.cloud import secretmanager  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SecretResolutionError(
            "google-cloud-secret-manager is required for GCP Secret Manager integration"
        ) from exc

    client = secretmanager.SecretManagerServiceClient()
    name = resource
    if "/versions/" not in name:
        name = f"{resource.rstrip('/')}/versions/latest"
    try:
        response = client.access_secret_version(name=name)
    except Exception as exc:  # pragma: no cover - GCP interaction
        raise SecretResolutionError(
            f"Failed accessing GCP secret '{name}': {exc}"
        ) from exc

    payload = response.payload.data.decode("utf-8")
    if key:
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - remote data dependent
            raise SecretResolutionError(
                f"Secret {name} is not JSON but key '{key}' was requested"
            ) from exc
        if key not in document:
            raise SecretResolutionError(f"Key '{key}' not present in secret {name}")
        value = str(document[key])
    else:
        value = payload

    metadata = {
        "name": name,
    }
    return ManagedSecret(value=value, metadata=metadata)


def _load_env_secret(identifier: str, key: str | None = None) -> ManagedSecret:
    payload = os.getenv(identifier)
    if payload is None:
        raise SecretResolutionError(f"Environment secret '{identifier}' not set")
    if key:
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SecretResolutionError(
                f"Environment secret '{identifier}' must contain JSON to access key '{key}'"
            ) from exc
        if key not in document:
            raise SecretResolutionError(
                f"Key '{key}' not present in environment secret '{identifier}'"
            )
        value = str(document[key])
    else:
        value = payload
    metadata = {"name": identifier, "provider": "env"}
    return ManagedSecret(value=value, metadata=metadata)


def _store_aws_secret(
    secret_id: str, value: str, *, key: str | None = None
) -> ManagedSecret:
    if _fallback_enabled():
        return _store_fallback_secret("aws-secrets", secret_id, value, key=key)
    try:  # pragma: no cover - requires boto3 dependency and credentials
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SecretUpdateError(
            "boto3 is required for AWS Secrets Manager integration"
        ) from exc

    client = boto3.client("secretsmanager")
    payload = value
    if key:
        try:
            existing = client.get_secret_value(SecretId=secret_id)
        except (
            BotoCoreError,
            ClientError,
        ) as exc:  # pragma: no cover - AWS interaction
            raise SecretUpdateError(
                f"Failed to fetch secret {secret_id} for update: {exc}"
            ) from exc
        document_raw = existing.get("SecretString", "{}")
        try:
            document = json.loads(document_raw or "{}")
        except json.JSONDecodeError as exc:  # pragma: no cover - remote data dependent
            raise SecretUpdateError(
                f"Secret {secret_id} must contain JSON to update key '{key}'"
            ) from exc
        document[key] = value
        payload = json.dumps(document)

    try:
        response = client.put_secret_value(SecretId=secret_id, SecretString=payload)
    except (BotoCoreError, ClientError) as exc:  # pragma: no cover - AWS interaction
        raise SecretUpdateError(f"Failed to update secret {secret_id}: {exc}") from exc
    metadata = {"arn": response.get("ARN", ""), "name": secret_id}
    return ManagedSecret(value=value, metadata=metadata)


def _store_vault_secret(
    secret_path: str, value: str, *, key: str | None = None
) -> ManagedSecret:
    if _fallback_enabled():
        return _store_fallback_secret("vault", secret_path, value, key=key)
    try:  # pragma: no cover - optional dependency
        import hvac  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SecretUpdateError("hvac is required for Vault integration") from exc

    addr = os.getenv("VAULT_ADDR")
    token = os.getenv("VAULT_TOKEN")
    if not addr or not token:
        raise SecretUpdateError(
            "VAULT_ADDR and VAULT_TOKEN must be set for Vault updates"
        )

    client = hvac.Client(url=addr, token=token)
    data = {}
    if key:
        try:
            existing = client.secrets.kv.v2.read_secret_version(path=secret_path)
            data = (existing.get("data") or {}).get("data") or {}
        except Exception:  # pragma: no cover - remote dependency variability
            data = {}
        data[str(key)] = value
    else:
        data = {"value": value}
    try:
        client.secrets.kv.v2.create_or_update_secret(path=secret_path, secret=data)
    except Exception as exc:  # pragma: no cover - remote dependency
        raise SecretUpdateError(
            f"Failed to update Vault secret '{secret_path}': {exc}"
        ) from exc

    metadata = {"path": secret_path, "version": "latest"}
    return ManagedSecret(value=value, metadata=metadata)


def _store_gcp_secret(
    resource: str, value: str, *, key: str | None = None
) -> ManagedSecret:
    if _fallback_enabled():
        return _store_fallback_secret("gcp-sm", resource, value, key=key)
    try:  # pragma: no cover - optional dependency
        from google.cloud import secretmanager  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SecretUpdateError(
            "google-cloud-secret-manager is required for GCP Secret Manager integration"
        ) from exc

    client = secretmanager.SecretManagerServiceClient()
    name = resource
    if "/versions/" in name:
        name = name.split("/versions/")[0]
    payload = value
    if key:
        document = {key: value}
        payload = json.dumps(document)
    parent = name
    try:
        response = client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload.encode("utf-8")},
            }
        )
    except Exception as exc:  # pragma: no cover - GCP interaction
        raise SecretUpdateError(
            f"Failed to add secret version for '{parent}': {exc}"
        ) from exc

    metadata = {"name": response.name}
    return ManagedSecret(value=value, metadata=metadata)


def _store_env_secret(
    identifier: str, value: str, *, key: str | None = None
) -> ManagedSecret:
    if key:
        payload = os.getenv(identifier)
        try:
            document = json.loads(payload or "{}")
        except json.JSONDecodeError as exc:
            raise SecretUpdateError(
                f"Environment secret '{identifier}' must contain JSON to update key '{key}'"
            ) from exc
        document[key] = value
        os.environ[identifier] = json.dumps(document)
        stored = document[key]
    else:
        os.environ[identifier] = value
        stored = value
    metadata = {"name": identifier, "provider": "env"}
    return ManagedSecret(value=stored, metadata=metadata)


_STORE_PROVIDERS: Dict[str, Callable[[str, str, str | None], ManagedSecret]] = {
    "aws-secrets": _store_aws_secret,
    "vault": _store_vault_secret,
    "gcp-sm": _store_gcp_secret,
    "env": _store_env_secret,
}


def _parse_spec(spec: str) -> tuple[str, str, str | None]:
    try:
        provider_and_id, _, key = spec.partition("#")
        provider, _, identifier = provider_and_id.partition("://")
    except ValueError as exc:  # pragma: no cover - defensive
        raise SecretResolutionError(f"Invalid secret specification: {spec}") from exc

    provider = provider.lower()
    if not provider or not identifier:
        raise SecretResolutionError(f"Invalid secret specification: {spec}")
    return provider, identifier, key or None


_PROVIDERS: Dict[str, Callable[[str, str | None], ManagedSecret]] = {
    "aws-secrets": _load_aws_secret,
    "vault": _load_vault_secret,
    "gcp-sm": _load_gcp_secret,
    "env": _load_env_secret,
}


@lru_cache(maxsize=64)
def resolve_managed_secret(spec: str) -> ManagedSecret:
    """Resolve a managed secret reference.

    The specification follows the scheme ``provider://identifier[#key]``.
    Currently supported providers:

    * ``aws-secrets`` – AWS Secrets Manager. The optional ``key`` portion will
      be used to extract a JSON property when the secret payload is structured.
    * ``vault`` – HashiCorp Vault KV v2 engine. When secrets contain multiple
      keys, one must be specified explicitly via ``#key``.
    * ``gcp-sm`` – Google Cloud Secret Manager. The identifier should be the
      secret resource path (``projects/.../secrets/<name>``) optionally including
      ``/versions/<version>``. When omitted, ``latest`` is used.
    """

    provider, identifier, key = _parse_spec(spec)
    if provider not in _PROVIDERS:
        raise SecretResolutionError(
            f"Unsupported secret provider '{provider}' in {spec}"
        )

    resolver = _PROVIDERS[provider]
    secret = resolver(identifier, key)
    logger.info("Loaded secret '%s' via provider '%s'", identifier, provider)
    return secret


def update_managed_secret(spec: str, value: str) -> ManagedSecret:
    """Update a managed secret with a new value."""

    provider, identifier, key = _parse_spec(spec)
    if provider not in _STORE_PROVIDERS:
        raise SecretUpdateError(f"Unsupported secret provider '{provider}' in {spec}")

    updater = _STORE_PROVIDERS[provider]
    secret = updater(identifier, value, key=key)
    logger.info("Updated secret '%s' via provider '%s'", identifier, provider)
    return secret


__all__ = [
    "ManagedSecret",
    "SecretResolutionError",
    "SecretUpdateError",
    "resolve_managed_secret",
    "update_managed_secret",
]
