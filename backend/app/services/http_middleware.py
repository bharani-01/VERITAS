"""ASGI middleware: collect metadata-only HTTP telemetry after each response."""

from __future__ import annotations

import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core import database as database
from app.services.http_classifier import should_track
from app.services.http_traffic import record_http_event

# Headers inspected for abuse heuristics (names + values truncated; never cookies/auth).
_WATCH_REQUEST_HEADERS = (
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-original-url",
    "x-rewrite-url",
    "x-real-ip",
    "forwarded",
    "host",
    "content-type",
    "accept",
)

_SECURITY_RESPONSE_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def _header_blob(request: Request) -> str | None:
    parts: list[str] = []
    for name in _WATCH_REQUEST_HEADERS:
        value = request.headers.get(name)
        if value:
            parts.append(f"{name}:{value[:120]}")
    return "\n".join(parts)[:800] if parts else None


def _security_response_headers(response: Response | None) -> dict[str, str] | None:
    if response is None:
        return None
    out: dict[str, str] = {}
    for name in _SECURITY_RESPONSE_HEADERS:
        value = response.headers.get(name)
        if value:
            out[name] = value[:200]
    return out or {}


class HttpTelemetryMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path or "/"
        if not should_track(path):
            return await call_next(request)

        started = time.perf_counter()
        response: Response | None = None
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            status_code = 500
            raise
        finally:
            duration_ms = int((time.perf_counter() - started) * 1000)
            try:
                forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip() or None
                direct = request.client.host if request.client else None
                ip = direct or forwarded
                with database.SessionLocal() as session:
                    record_http_event(
                        session,
                        method=request.method,
                        path=path,
                        query=request.url.query or None,
                        status_code=status_code,
                        duration_ms=duration_ms,
                        ip_address=ip,
                        user_agent=request.headers.get("user-agent"),
                        session_cookie=request.cookies.get("veritas_session"),
                        origin=request.headers.get("origin"),
                        referer=request.headers.get("referer"),
                        request_host=request.headers.get("host"),
                        header_blob=_header_blob(request),
                        response_headers=_security_response_headers(response),
                    )
            except Exception:
                # Fail-open: never break the request path for telemetry errors.
                pass
