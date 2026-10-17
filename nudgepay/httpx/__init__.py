from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

from . import _types
from ._client import USE_CLIENT_DEFAULT, UseClientDefault

__all__ = [
    "BaseTransport",
    "ByteStream",
    "Client",
    "Headers",
    "Request",
    "Response",
    "URL",
    "USE_CLIENT_DEFAULT",
    "UseClientDefault",
]


class Headers:
    def __init__(self, initial: _types.HeaderTypes | None = None) -> None:
        self._items: List[Tuple[str, str]] = []
        if initial:
            if isinstance(initial, Mapping):
                for key, value in initial.items():
                    self.add(key, value)
            else:
                for key, value in initial:
                    self.add(key, value)

    def add(self, key: str, value: str) -> None:
        self._items.append((str(key), str(value)))

    def get(self, key: str, default: str | None = None) -> str | None:
        key_lower = key.lower()
        for existing_key, existing_value in reversed(self._items):
            if existing_key.lower() == key_lower:
                return existing_value
        return default

    def multi_items(self) -> List[Tuple[str, str]]:
        return list(self._items)

    def copy(self) -> "Headers":
        return Headers(self._items)

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._items)

    def update(self, other: _types.HeaderTypes | None) -> None:
        if not other:
            return
        if isinstance(other, Mapping):
            items = other.items()
        else:
            items = other
        for key, value in items:
            self.add(str(key), str(value))

    def setdefault(self, key: str, value: str) -> str:
        current = self.get(key)
        if current is None:
            self.add(key, value)
            return value
        return current

    def __iter__(self) -> Iterable[Tuple[str, str]]:
        return iter(self._items)


@dataclass
class URL:
    raw: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.raw)
        self.scheme: str = parsed.scheme or "http"
        self.host: str = parsed.hostname or ""
        self.port: Optional[int] = parsed.port
        path = parsed.path or "/"
        query = parsed.query
        self.path: str = path
        if query:
            self.raw_path: bytes = f"{path}?{query}".encode("ascii", "ignore")
        else:
            self.raw_path = path.encode("ascii", "ignore")
        self.query: bytes = query.encode("ascii", "ignore")
        netloc = parsed.netloc or ""
        self.netloc: bytes = netloc.encode("ascii", "ignore")

    def __str__(self) -> str:  # pragma: no cover - debugging helper
        if self.query:
            query = "?" + self.query.decode("ascii", "ignore")
        else:
            query = ""
        return f"{self.scheme}://{self.netloc.decode('ascii', 'ignore')}{self.path}{query}"


class Request:
    def __init__(
        self,
        method: str,
        url: URL,
        *,
        headers: Headers | None = None,
        content: bytes = b"",
    ) -> None:
        self.method = method.upper()
        self.url = url
        self.headers = headers or Headers()
        self._content = content

    def read(self) -> bytes:
        return self._content


class ByteStream:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class Response:
    def __init__(
        self,
        status_code: int = 200,
        headers: Sequence[Tuple[str, str]] | None = None,
        stream: ByteStream | None = None,
        request: Request | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = Headers(headers or [])
        self.stream = stream or ByteStream(b"")
        self.request = request
        self.history: List["Response"] = []

    @property
    def content(self) -> bytes:
        return self.stream.read()

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.text)


class BaseTransport:
    def handle_request(self, request: Request) -> Response:  # pragma: no cover - interface
        raise NotImplementedError


class Client:
    def __init__(
        self,
        *,
        app: Any,
        base_url: str = "http://testserver",
        headers: Mapping[str, str] | None = None,
        transport: BaseTransport | None = None,
        follow_redirects: bool = True,
        cookies: _types.CookieTypes | None = None,
    ) -> None:
        if transport is None:
            raise ValueError("A transport implementation is required")
        self.app = app
        self.base_url = base_url.rstrip("/") or "http://testserver"
        self._transport = transport
        self.follow_redirects = follow_redirects
        self._cookie_store: Dict[str, str] = {}
        if cookies:
            self._store_cookies(cookies)
        self._default_headers = Headers(headers or {})

    # -- cookie handling ---------------------------------------------------
    @property
    def cookies(self) -> Dict[str, str]:
        """Return a copy of the cookie jar for inspection."""

        return dict(self._cookie_store)

    def _store_cookies(self, cookies: _types.CookieTypes) -> None:
        if isinstance(cookies, Mapping):
            items = cookies.items()
        elif isinstance(cookies, str):
            items = [tuple(pair.split("=", 1)) for pair in cookies.split("; ") if "=" in pair]
        else:
            items = cookies
        for key, value in items:
            self._cookie_store[str(key)] = str(value)

    def _update_cookie_jar(self, headers: Headers) -> None:
        for key, value in headers.multi_items():
            if key.lower() != "set-cookie":
                continue
            cookie_pair, _, rest = value.partition(";")
            if "=" not in cookie_pair:
                continue
            name, cookie_value = cookie_pair.split("=", 1)
            normalized_name = name.strip()
            normalized_value = cookie_value.strip()
            lower_rest = rest.lower()
            if normalized_value.lower() in {"", '""', "null"} or "max-age=0" in lower_rest or "expires=thu, 01 jan 1970" in lower_rest:
                self._cookie_store.pop(normalized_name, None)
            else:
                self._cookie_store[normalized_name] = normalized_value

    # -- context management -------------------------------------------------
    def __enter__(self) -> "Client":  # pragma: no cover - compatibility
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # pragma: no cover - compatibility
        self.close()

    def close(self) -> None:  # pragma: no cover - compatibility
        return None

    # -- helpers ------------------------------------------------------------
    def _merge_url(self, url: _types.URLTypes) -> URL:
        if isinstance(url, URL):
            return url
        url_str = str(url)
        if url_str.startswith(("http://", "https://", "ws://", "wss://")):
            return URL(url_str)
        joined = urljoin(self.base_url + "/", url_str.lstrip("/"))
        return URL(joined)

    def _prepare_body(
        self,
        *,
        content: _types.RequestContent | None = None,
        data: Any = None,
        json_data: Any = None,
    ) -> Tuple[bytes, Headers]:
        headers = Headers()
        if content is not None:
            if isinstance(content, (bytes, bytearray)):
                body = bytes(content)
            else:
                body = str(content).encode("utf-8")
            return body, headers
        if json_data is not None:
            body = json.dumps(json_data).encode("utf-8")
            headers.setdefault("content-type", "application/json")
            return body, headers
        if data is None:
            return b"", headers
        if isinstance(data, (bytes, bytearray)):
            return bytes(data), headers
        if isinstance(data, str):
            return data.encode("utf-8"), headers
        if isinstance(data, Mapping):
            body = urlencode({k: v for k, v in data.items()}).encode("utf-8")
            headers.setdefault(
                "content-type", "application/x-www-form-urlencoded"
            )
            return body, headers
        raise TypeError("Unsupported request body type")

    # -- HTTP verbs ---------------------------------------------------------
    def request(
        self,
        method: str,
        url: _types.URLTypes,
        *,
        content: _types.RequestContent | None = None,
        data: Any = None,
        files: _types.RequestFiles | None = None,
        json: Any = None,
        params: _types.QueryParamTypes | None = None,
        headers: _types.HeaderTypes | None = None,
        cookies: _types.CookieTypes | None = None,
        auth: _types.AuthTypes | UseClientDefault = USE_CLIENT_DEFAULT,
        follow_redirects: bool | None = None,
        allow_redirects: bool | None = None,
        timeout: _types.TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT,
        extensions: Dict[str, Any] | None = None,
    ) -> Response:
        del files, auth, timeout, extensions  # Unused hooks
        if follow_redirects is None and allow_redirects is not None:
            follow_redirects = allow_redirects
        follow = self.follow_redirects if follow_redirects is None else bool(follow_redirects)
        url_obj = self._merge_url(url)
        if params:
            if isinstance(params, str):
                query_string = params
            elif isinstance(params, Mapping):
                query_string = urlencode(params, doseq=True)
            else:
                query_string = urlencode(list(params), doseq=True)
            if query_string:
                suffix = f"?{query_string}"
                url_obj = URL(str(url_obj) + suffix)

        current_method = method.upper()
        current_url = url_obj
        current_content = content
        current_data = data
        current_json = json
        redirect_history: List[Response] = []

        for _ in range(20):  # Cap redirect depth similar to httpx defaults
            body, body_headers = self._prepare_body(
                content=current_content, data=current_data, json_data=current_json
            )
            request_headers = self._default_headers.copy()
            request_headers.update(body_headers.multi_items())
            request_headers.update(headers)

            cookie_components: List[str] = []
            jar_value = (
                self._format_cookies(self._cookie_store.items())
                if self._cookie_store
                else ""
            )
            if jar_value:
                cookie_components.append(jar_value)
            if cookies is not None:
                cookie_components.append(self._format_cookies(cookies))
            existing_header = request_headers.get("cookie")
            if existing_header:
                cookie_components.append(existing_header)
            if cookie_components:
                combined = "; ".join(part for part in cookie_components if part)
                request_headers.setdefault("cookie", combined)

            request = Request(current_method, current_url, headers=request_headers, content=body)
            response = self._transport.handle_request(request)
            if response.request is None:
                response.request = request
            self._update_cookie_jar(response.headers)

            redirect_codes = {301, 302, 303, 307, 308}
            if not follow or response.status_code not in redirect_codes:
                if redirect_history:
                    response.history = list(redirect_history)
                return response

            location = response.headers.get("location")
            if location is None:
                if redirect_history:
                    response.history = list(redirect_history)
                return response

            redirect_history.append(response)
            current_url = self._merge_url(location)

            if response.status_code == 303 or (
                response.status_code in {301, 302}
                and request.method not in {"GET", "HEAD"}
            ):
                current_method = "GET"
                current_content = None
                current_data = None
                current_json = None
            else:
                current_method = request.method
                # Preserve the original payload for 307/308 redirects
                if current_content is not None:
                    pass  # content already provided explicitly
                elif current_data is not None:
                    pass
                elif current_json is not None:
                    pass
                else:
                    current_content = body

        raise RuntimeError("Exceeded maximum redirect depth")

    def _format_cookies(
        self, cookies: _types.CookieTypes
    ) -> str:  # pragma: no cover - simple helper
        if isinstance(cookies, str):
            return cookies
        if isinstance(cookies, Mapping):
            items = cookies.items()
        else:
            items = cookies
        return "; ".join(f"{k}={v}" for k, v in items)

    def get(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("DELETE", url, **kwargs)


# Backwards compatibility names for starlette
HeadersLike = Headers
