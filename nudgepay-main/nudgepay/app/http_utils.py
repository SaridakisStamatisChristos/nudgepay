"""Helpers for performing outbound HTTP requests securely."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from urllib.parse import urlparse
import urllib.request


@contextmanager
def safe_urlopen(
    request: urllib.request.Request,
    *,
    timeout: float | None = None,
    allowed_schemes: Iterable[str] = ("https", "http"),
) -> Iterator[urllib.response.addinfourl]:
    """Open ``request`` only when the URL uses an allowed scheme."""

    schemes = {scheme.lower() for scheme in allowed_schemes}
    if not schemes:
        raise ValueError("At least one URL scheme must be permitted")

    parsed = urlparse(request.full_url)
    scheme = parsed.scheme.lower()
    if scheme not in schemes:
        raise ValueError(f"Refusing to open URL with disallowed scheme: {request.full_url}")

    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - scheme validated above
        yield response


__all__ = ["safe_urlopen"]
