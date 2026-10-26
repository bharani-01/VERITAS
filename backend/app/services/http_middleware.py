"""ASGI middleware: collect metadata-only HTTP telemetry and enforce Active IPS quarantine."""

from __future__ import annotations

import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.core import database as database
from app.services.http_classifier import should_track
from app.services.http_traffic import is_ip_quarantined, record_http_event

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


def _extract_client_ip(request: Request) -> str | None:
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    real_ip = (request.headers.get("x-real-ip") or "").strip()
    if real_ip:
        return real_ip
    return request.client.host if request.client else None


class HttpTelemetryMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path or "/"
        ip = _extract_client_ip(request)

        # Enforce Active IPS Quarantine (never lock out /admin/* or /auth/* so admins can log in and unblock)
        if ip and not path.startswith("/admin") and not path.startswith("/auth"):
            blocked, reason = is_ip_quarantined(ip)
            if blocked:
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "IP address temporarily quarantined by VERITAS Active IPS",
                        "reason": reason,
                    },
                )

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
                pass
