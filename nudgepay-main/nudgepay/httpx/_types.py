from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping, Sequence, Tuple, Union

if TYPE_CHECKING:  # pragma: no cover - typing-only import
    from . import URL

URLTypes = Union[str, "URL"]
RequestContent = Union[bytes, bytearray, str]
RequestFiles = Any
QueryParamTypes = Union[str, Mapping[str, Any], Sequence[Tuple[str, Any]]]
HeaderTypes = Union[Mapping[str, str], Sequence[Tuple[str, str]]]
CookieTypes = Union[Mapping[str, str], Sequence[Tuple[str, str]], str]
AuthTypes = Any
TimeoutTypes = Union[float, Tuple[float, float, float, float]]
