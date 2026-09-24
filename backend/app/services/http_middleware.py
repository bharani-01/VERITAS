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
                    )
            except Exception:
                # Fail-open: never break the request path for telemetry errors.
                pass
