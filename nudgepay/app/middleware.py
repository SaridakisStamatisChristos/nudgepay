"""Custom middleware used by the application."""

from __future__ import annotations

import logging
import time
import uuid
from urllib.parse import parse_qs

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp

from .config import get_settings
from .csrf import _COOKIE_NAME, issue_csrf_token, validate_csrf_token
from .logging_utils import request_id_ctx_var
from .metrics import observe_http_request


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id to each request and emit access logs."""

    def __init__(self, app: ASGIApp, *, header_name: str = "X-Request-ID") -> None:
        super().__init__(app)
        self.header_name = header_name
        self.logger = logging.getLogger("nudgepay.request")

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        request_id = request.headers.get(self.header_name) or uuid.uuid4().hex
        request.state.request_id = request_id
        token = request_id_ctx_var.set(request_id)
        start = time.perf_counter()
        route_template = getattr(request.scope.get("route"), "path", request.url.path)

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - start) * 1000, 3)
            observe_http_request(request.method, route_template, 500, duration_ms / 1000)
            self.logger.exception(
                "request.failed",
                extra={
                    "request_id": request_id,
                    "path": str(request.url.path),
                    "method": request.method,
                    "duration_ms": duration_ms,
                },
            )
            raise
        else:
            duration_ms = round((time.perf_counter() - start) * 1000, 3)
            response.headers[self.header_name] = request_id
            observe_http_request(
                request.method,
                route_template,
                response.status_code,
                duration_ms / 1000,
            )
            self.logger.info(
                "request.completed",
                extra={
                    "request_id": request_id,
                    "path": str(request.url.path),
                    "method": request.method,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                },
            )
            return response
        finally:
            request_id_ctx_var.reset(token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforce a modern set of security headers on all responses."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        content_security_policy: str,
        hsts_seconds: int,
        force_https: bool,
    ) -> None:
        super().__init__(app)
        self.content_security_policy = content_security_policy
        self.hsts_seconds = hsts_seconds
        self.force_https = force_https

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", self.content_security_policy)

        if self.hsts_seconds and (self.force_https or request.url.scheme == "https"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={self.hsts_seconds}; includeSubDomains",
            )

        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforce CSRF token validation for state-changing requests."""

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        settings = get_settings()
        self._cookie_name = _COOKIE_NAME
        self._secure = settings.session_https_only
        self._same_site = settings.session_cookie_same_site
        self._exempt_paths = tuple(settings.csrf_exempt_paths)

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        path = request.url.path
        if any(
            path == candidate or (candidate.endswith("*") and path.startswith(candidate[:-1]))
            for candidate in self._exempt_paths
        ):
            return await call_next(request)

        token = issue_csrf_token(request)
        request.state.csrf_token = token

        if request.method.upper() not in self.SAFE_METHODS:
            candidates = [
                request.headers.get("X-CSRF-Token"),
                request.cookies.get(self._cookie_name),
            ]
            content_type = request.headers.get("content-type", "")
            if "application/x-www-form-urlencoded" in content_type:
                body_bytes = await request.body()
                if body_bytes:
                    try:
                        parsed = parse_qs(body_bytes.decode("utf-8"), keep_blank_values=True)
                    except UnicodeDecodeError:
                        parsed = {}
                    token_value = parsed.get("_csrf_token")
                    if token_value:
                        candidates.append(token_value[-1])
            elif "multipart/form-data" in content_type:
                form = await request.form()
                candidates.append(form.get("_csrf_token"))
            try:
                validate_csrf_token(request, candidates)
            except PermissionError:
                return PlainTextResponse("Forbidden", status_code=403)

        response = await call_next(request)
        response.set_cookie(
            self._cookie_name,
            token,
            httponly=False,
            secure=self._secure,
            samesite=self._same_site,
        )
        response.headers.setdefault("X-CSRF-Token", token)
        return response


__all__ = ["CSRFMiddleware", "RequestContextMiddleware", "SecurityHeadersMiddleware"]

