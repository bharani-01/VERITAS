"""Rate limiting engine for VERITAS: multi-tier rule enforcement across all routes."""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable

from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp
from sqlalchemy.orm import Session

from app.core.config import APP_ENV
from app.services.http_classifier import (
    _CMD,
    _PATH_TRAV,
    _SCANNER_UA,
    _SQLI,
    _SSRF,
    _SSTI,
    _XSS,
)

# Paths exempt from rate limiting (assets, liveness, session check, long-lived websockets)
EXEMPT_PREFIXES = (
    "/assets",
    "/brand",
    "/favicon",
    "/robots",
    "/sitemap",
    "/site.webmanifest",
    "/icons",
    "/health",
    "/auth/me",
    "/admin/audit-events/ws",
)


@dataclass
class RateLimitRule:
    name: str
    description: str
    scope: str
    limit: int
    window_seconds: int
    path_regex: str | None = None
    methods: tuple[str, ...] | None = None
    matcher: Callable[[Request], bool] | None = None
    exempt_in_test: bool = True


def get_client_ip(request: Request) -> str:
    """Extract real client IP considering forwarded proxies."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def _is_suspicious_payload_or_ua(request: Request) -> bool:
    """Heuristic detection of scanner tools or attack signatures."""
    ua = request.headers.get("user-agent") or ""
    if _SCANNER_UA.search(ua):
        return True

    # Check path & query string
    path_and_query = f"{request.url.path}?{request.url.query or ''}"
    for pat in (_SQLI, _XSS, _PATH_TRAV, _CMD, _SSRF, _SSTI):
        if pat.search(path_and_query):
            return True

    return False


class RateLimiter:
    """
    Sliding window rate limiter with rule matching and statistics tracking.
    Preserves self.events for backwards compatibility with tests.
    """

    def __init__(self) -> None:
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.stats: dict[str, int] = defaultdict(int)
        self.rules: list[RateLimitRule] = self._init_rules()

    def _init_rules(self) -> list[RateLimitRule]:
        return [
            # 1. Threat & Scanner Mitigation: Aggressive throttling for scanners & active exploit payloads
            RateLimitRule(
                name="threat_scanner",
                description="Automated security scanners & malicious attack payloads",
                scope="Heuristic attack signatures / Scanner User-Agents",
                limit=10,
                window_seconds=60,
                matcher=_is_suspicious_payload_or_ua,
                exempt_in_test=True,
            ),
            # 2. Authentication Login: Brute force & credential stuffing defense
            RateLimitRule(
                name="auth_login",
                description="Sign-in brute-force protection",
                scope="POST /auth/login",
                limit=10,
                window_seconds=300,
                path_regex=r"^/auth/login",
                methods=("POST",),
                exempt_in_test=False,  # Enforced during identity test suite
            ),
            # 3. Authentication Signup: Bot account registration defense
            RateLimitRule(
                name="auth_signup",
                description="Account registration spam defense",
                scope="POST /auth/signup",
                limit=5,
                window_seconds=3600,
                path_regex=r"^/auth/signup",
                methods=("POST",),
                exempt_in_test=False,
            ),
            # 4. Authentication Reset: Email flooding & enumeration defense
            RateLimitRule(
                name="auth_password_reset",
                description="Password reset & verification email flood defense",
                scope="POST /auth/request-password-reset, resend-verification",
                limit=3,
                window_seconds=3600,
                path_regex=r"^/auth/(request-password-reset|resend-verification)",
                methods=("POST",),
                exempt_in_test=False,
            ),
            # 5. Authentication Token Confirm: Token guessing defense
            RateLimitRule(
                name="auth_confirm_reset",
                description="Token verification & password reset completion",
                scope="POST /auth/password-reset/confirm, verify-email",
                limit=5,
                window_seconds=900,
                path_regex=r"^/auth/(password-reset/confirm|verify-email)",
                methods=("POST",),
                exempt_in_test=False,
            ),
            # 6. Workspace Scans: Worker & Semgrep CPU compute quota
            RateLimitRule(
                name="workspace_scans",
                description="Security scan runner concurrency & compute quota",
                scope="POST /workspace/projects/*/scans",
                limit=10,
                window_seconds=300,
                path_regex=r"^/workspace/projects/[^/]+/scans",
                methods=("POST",),
                exempt_in_test=True,
            ),
            # 7. AI Triage: Groq LLM API quota protection
            RateLimitRule(
                name="ai_triage",
                description="Groq AI triage & copilot request quota",
                scope="POST /workspace/ai/*, /triage",
                limit=20,
                window_seconds=300,
                path_regex=r"^/workspace/(ai|projects/[^/]+/findings/[^/]+/triage)",
                methods=("POST",),
                exempt_in_test=True,
            ),
            # 8. Admin Mutations: Privileged administrative operation safety
            RateLimitRule(
                name="admin_mutations",
                description="Privileged admin modifications rate limit",
                scope="POST/PUT/PATCH/DELETE /admin/(users|projects|fs)/*",
                limit=40,
                window_seconds=60,
                path_regex=r"^/admin/(users|projects|fs)",
                methods=("POST", "PUT", "PATCH", "DELETE"),
                exempt_in_test=True,
            ),
            # 9. Webhooks: GitHub webhook replay/flood protection
            RateLimitRule(
                name="webhooks",
                description="GitHub webhook event ingestion rate limit",
                scope="POST /webhooks/*",
                limit=60,
                window_seconds=60,
                path_regex=r"^/webhooks",
                methods=("POST",),
                exempt_in_test=True,
            ),
            # 10. Global API Baseline: Catch-all request rate limit across EVERY route
            RateLimitRule(
                name="global_api",
                description="Baseline global IP rate limit across all application routes",
                scope="Catch-all baseline for all API endpoints",
                limit=300,
                window_seconds=60,
                path_regex=r"^/(auth|admin|workspace|public|api)",
                exempt_in_test=True,
            ),
        ]

    def check_bucket(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int, int]:
        """
        Check rate limit bucket.
        Returns: (allowed: bool, remaining: int, retry_after: int)
        """
        now = time.monotonic()
        bucket = self.events[key]
        while bucket and bucket[0] < now - window_seconds:
            bucket.popleft()

        if len(bucket) >= limit:
            oldest = bucket[0]
            retry_after = max(1, int(oldest + window_seconds - now))
            return False, 0, retry_after

        bucket.append(now)
        remaining = max(0, limit - len(bucket))
        return True, remaining, 0

    def check(self, key: str, limit: int, window_seconds: int) -> None:
        """Original check method throwing HTTPException(429) for backward compatibility."""
        allowed, _, retry_after = self.check_bucket(key, limit, window_seconds)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {retry_after} seconds before trying again.",
                headers={"Retry-After": str(retry_after)},
            )

    def evaluate(self, request: Request) -> tuple[RateLimitRule | None, str | None, bool, int, int]:
        """
        Evaluate an incoming HTTP request against configured rate limit rules.
        Returns: (matching_rule, bucket_key, allowed, remaining, retry_after)
        """
        path = request.url.path or "/"

        # Check exemption prefixes
        if any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES):
            return None, None, True, 0, 0

        is_test = APP_ENV == "test"
        ip = get_client_ip(request)

        for rule in self.rules:
            if is_test and rule.exempt_in_test:
                continue

            # Method filter
            if rule.methods and request.method not in rule.methods:
                continue

            # Path regex filter
            if rule.path_regex and not re.search(rule.path_regex, path):
                continue

            # Custom matcher (e.g. threat detection)
            if rule.matcher and not rule.matcher(request):
                continue

            # Rule matched! Build bucket key
            bucket_key = f"{rule.name}:{ip}"
            allowed, remaining, retry_after = self.check_bucket(
                bucket_key, rule.limit, rule.window_seconds
            )
            return rule, bucket_key, allowed, remaining, retry_after

        return None, None, True, 0, 0

    def get_rules_info(self) -> list[dict[str, Any]]:
        """Export rule descriptions and statistics for the admin dashboard."""
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "scope": rule.scope,
                "limit": rule.limit,
                "window_seconds": rule.window_seconds,
                "triggered_count": self.stats.get(rule.name, 0),
            }
            for rule in self.rules
        ]


rate_limiter = RateLimiter()


def check_rate_limit(
    db: Session,
    request: Request,
    key: str,
    limit: int,
    window_seconds: int,
) -> None:
    """
    Enforce rate limit and record a 429 audit event when blocked.
    Prevents double-counting if already processed by RateLimitMiddleware.
    """
    checked_keys = getattr(request.state, "_rate_limit_keys_checked", set())
    if key in checked_keys:
        return
    checked_keys.add(key)
    request.state._rate_limit_keys_checked = checked_keys

    try:
        rate_limiter.check(key, limit, window_seconds)
    except HTTPException as exc:
        if exc.status_code == 429:
            from app.services.audit import audit

            rule_name = key.split(":", 1)[0]
            rate_limiter.stats[rule_name] += 1
            audit(
                db,
                request,
                "rate_limited",
                after={"scope": rule_name},
                status_code=429,
            )
            db.commit()
        raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Global ASGI middleware applying rate limiting rules to every route.
    Returns RFC 6585 compliant 429 responses with Retry-After and rate limit headers.
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        rule, key, allowed, remaining, retry_after = rate_limiter.evaluate(request)

        if rule and key:
            # Mark key as evaluated to avoid double counting in route-level checks
            request.state._rate_limit_keys_checked = {key}

            if not allowed:
                rate_limiter.stats[rule.name] += 1

                # Record 429 audit event and broadcast to live admin consoles
                try:
                    from app.core.database import SessionLocal
                    from app.services.audit import audit

                    with SessionLocal() as session:
                        audit(
                            session,
                            request,
                            "rate_limited",
                            after={
                                "rule": rule.name,
                                "scope": rule.name,
                                "description": rule.description,
                                "limit": rule.limit,
                                "window_seconds": rule.window_seconds,
                                "retry_after": retry_after,
                                "path": request.url.path,
                                "method": request.method,
                                "client_ip": get_client_ip(request),
                            },
                            status_code=429,
                        )
                        session.commit()
                except Exception:
                    pass

                # Return RFC 6585 standard 429 response
                reset_epoch = int(time.time() + retry_after)
                headers = {
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(rule.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_epoch),
                    "X-RateLimit-Rule": rule.name,
                }
                body = {
                    "detail": f"Rate limit exceeded for rule '{rule.name}'. Please retry after {retry_after}s.",
                    "rule": rule.name,
                    "retry_after": retry_after,
                    "limit": rule.limit,
                    "window_seconds": rule.window_seconds,
                }
                return JSONResponse(status_code=429, content=body, headers=headers)

        response = await call_next(request)

        if rule:
            response.headers["X-RateLimit-Limit"] = str(rule.limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Rule"] = rule.name

        return response
