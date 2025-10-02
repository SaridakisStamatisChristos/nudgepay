"""Top-level package for the NudgePay application.

This module ensures the repository can be imported as ``nudgepay`` during
unit tests and other tooling that relies on absolute imports.
"""

from importlib import import_module
from types import ModuleType
from typing import TYPE_CHECKING

__all__ = ["app", "scripts"]


def __getattr__(name: str) -> ModuleType:
    if name in __all__:
        return import_module(f"nudgepay.{name}")
    raise AttributeError(f"module 'nudgepay' has no attribute {name!r}")


if TYPE_CHECKING:  # pragma: no cover
    from . import app as app  # type: ignore[F401]
    from . import scripts as scripts  # type: ignore[F401]
