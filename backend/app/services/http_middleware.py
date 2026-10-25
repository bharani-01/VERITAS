"""ASGI middleware: collect metadata-only HTTP telemetry after each response."""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core import database as database
from app.services.http_classifier import should_track
from app.services.http_traffic import record_http_event

# Paths exempted from automatic audit logging to avoid recursive loops during UI polling
_AUDIT_EXCLUDE_PATHS = (
    "/admin/audit-events",
    "/admin/audit-stats",
    "/admin/rate-limits",
    "/admin/http-requests",
    "/admin/security-overview",
    "/admin/security-analyze",
    "/health",
)

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|auth|credential|access_token|private_key|session)",
    re.IGNORECASE,
)


def _redact_data(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            str(k): ("[REDACTED]" if _SENSITIVE_KEY_RE.search(str(k)) else _redact_data(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_data(item) for item in obj]
    if isinstance(obj, str) and len(obj) > 3000:
        return obj[:3000] + "... [truncated]"
    return obj


async def _extract_payload(request: Request) -> str | None:
    parts: dict[str, Any] = {}
    if request.url.query:
        try:
            from urllib.parse import parse_qs

            raw_qs = parse_qs(request.url.query)
            redacted_qs = {
                k: ("[REDACTED]" if _SENSITIVE_KEY_RE.search(k) else v)
                for k, v in raw_qs.items()
            }
            parts["query"] = {k: v[0] if len(v) == 1 else v for k, v in redacted_qs.items()}
        except Exception:
            parts["query"] = request.url.query[:500]

    content_type = request.headers.get("content-type", "")
    content_length = request.headers.get("content-length")
    if "multipart/form-data" in content_type:
        parts["body"] = "[multipart/form-data upload]"
    elif content_length and int(content_length) > 200_000:
        parts["body"] = f"[payload exceeds 200KB: {content_length} bytes]"
    elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            body_bytes = await request.body()
            if body_bytes:
                if "application/json" in content_type:
                    parsed = json.loads(body_bytes.decode("utf-8", errors="replace"))
                    parts["body"] = _redact_data(parsed)
                else:
                    text = body_bytes.decode("utf-8", errors="replace")[:4000]
                    parts["body"] = text
        except Exception:
            pass

    if not parts:
        return None
    if len(parts) == 1 and "body" in parts:
        if isinstance(parts["body"], (dict, list)):
            return json.dumps(parts["body"], indent=2)
        return str(parts["body"])
    return json.dumps(parts, indent=2)

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

        try:
            request.state.audit_payload = await _extract_payload(request)
        except Exception:
            pass

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

                    # Also log to AuditEvent if not already audited by an explicit endpoint and not an exempted polling path
                    if not getattr(request.state, "audit_logged", False):
                        if not any(path.startswith(p) for p in _AUDIT_EXCLUDE_PATHS):
                            from app.services.audit import record_audit_api_event

                            record_audit_api_event(
                                session,
                                request=request,
                                method=request.method,
                                path=path,
                                query=request.url.query or None,
                                status_code=status_code,
                                ip_address=ip,
                                user_agent=request.headers.get("user-agent"),
                                session_cookie=request.cookies.get("veritas_session"),
                                payload=getattr(request.state, "audit_payload", None),
                            )
            except Exception:
                # Fail-open: never break the request path for telemetry errors.
                pass
