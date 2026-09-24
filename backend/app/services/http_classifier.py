"""Heuristic HTTP request classification (path/query only — no bodies)."""

from __future__ import annotations

import re
from urllib.parse import urlparse

_SQLI = re.compile(
    r"(?i)("
    r"('\s*or\s+'?\d|'?\s*or\s+\d+\s*=\s*\d|"
    r"union\s+select|sleep\s*\(|benchmark\s*\(|"
    r"information_schema|xp_cmdshell|;\s*drop\s+|"
    r"/\*.*\*/|--\s|waitfor\s+delay)"
    r")"
)

_XSS = re.compile(
    r"(?i)("
    r"<script|javascript:|onerror\s*=|onload\s*=|"
    r"document\.cookie|<img\s|svg/onload|eval\s*\(|"
    r"%3Cscript|&#x?3c"
    r")"
)

_SENSITIVE_QUERY = re.compile(r"(?i)(password|token|secret|authorization|cookie|api[_-]?key|session)")

_TRACKED_PREFIXES = ("/auth", "/admin", "/workspace", "/webhooks", "/health")
_SKIP_PREFIXES = (
    "/assets",
    "/brand",
    "/favicon",
    "/apple-touch",
    "/robots",
    "/sitemap",
    "/site.webmanifest",
    "/icons",
)

COUNTERMEASURES = {
    "sqli": [
        "Use parameterized queries / ORM bind parameters — never concatenate user input into SQL.",
        "Validate and reject unexpected characters in IDs and filters.",
        "Least-privilege DB accounts; disable dangerous DB functions in app roles.",
    ],
    "xss": [
        "Encode output for HTML/JS/URL contexts; prefer framework auto-escaping.",
        "Set a strict Content-Security-Policy; avoid inline scripts where possible.",
        "Sanitize any rich-text input with a vetted allow-list sanitizer.",
    ],
    "csrf": [
        "Require SameSite cookies and verify Origin/Referer on state-changing requests.",
        "Use anti-CSRF tokens for cookie-authenticated mutations.",
        "Prefer Authorization headers over cookies for API clients when feasible.",
    ],
    "auth_anomaly": [
        "Enforce rate limits and account lockouts on repeated auth failures.",
        "Alert on bursts of 401/403/429 from a single IP.",
        "Require MFA for admin accounts and review failed sign-in audit events.",
    ],
}


def should_track(path: str) -> bool:
    if not path:
        return False
    lowered = path.lower()
    if any(lowered.startswith(p) for p in _SKIP_PREFIXES):
        return False
    if any(lowered.startswith(p) for p in _TRACKED_PREFIXES):
        return True
    # Skip SPA document shells and unknown static paths
    if "." in path.rsplit("/", 1)[-1]:
        return False
    return False


def sanitize_path(path: str, query: str | None) -> str:
    """Store path + redacted query (truncate; strip secret-looking params)."""
    base = (path or "/")[:400]
    if not query:
        return base
    parts: list[str] = []
    for chunk in query.split("&")[:24]:
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        if _SENSITIVE_QUERY.search(key) or _SENSITIVE_QUERY.search(value):
            parts.append(f"{key}=[redacted]")
        else:
            parts.append(f"{key}={value[:80]}" if value else key)
    q = "&".join(parts)
    combined = f"{base}?{q}" if q else base
    return combined[:512]


def _origin_host(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlparse(value)
        return (parsed.hostname or "").lower() or None
    except Exception:
        return None


def classify_request(
    *,
    method: str,
    path: str,
    query: str | None,
    status_code: int,
    has_session_cookie: bool,
    origin: str | None,
    referer: str | None,
    request_host: str | None,
) -> tuple[str, str, list[str]]:
    """
    Returns (classification, severity, signals).
    Priority: sqli > xss > csrf > auth_anomaly > clean.
    """
    haystack = f"{path}?{query or ''}"
    signals: list[str] = []
    classification = "clean"
    severity = "info"

    if _SQLI.search(haystack):
        classification = "sqli"
        severity = "critical"
        signals.append("SQL injection pattern in path/query")
    elif _XSS.search(haystack):
        classification = "xss"
        severity = "high"
        signals.append("XSS pattern in path/query")
    else:
        method_u = (method or "GET").upper()
        if method_u in {"POST", "PUT", "PATCH", "DELETE"} and has_session_cookie:
            host = (request_host or "").split(":")[0].lower()
            o_host = _origin_host(origin)
            r_host = _origin_host(referer)
            if not origin and not referer:
                classification = "csrf"
                severity = "high"
                signals.append("State-changing request with session cookie but no Origin/Referer")
            elif host and ((o_host and o_host != host) or (not o_host and r_host and r_host != host)):
                classification = "csrf"
                severity = "high"
                signals.append("Origin/Referer host mismatch for cookie session")

    if classification == "clean":
        path_l = (path or "").lower()
        if path_l.startswith("/auth") and status_code in (401, 403, 429):
            classification = "auth_anomaly"
            severity = "medium" if status_code != 429 else "high"
            signals.append(f"Auth path returned {status_code}")
        elif status_code == 429:
            classification = "auth_anomaly"
            severity = "medium"
            signals.append("Rate limited")
        elif status_code >= 500:
            severity = "low"
            signals.append(f"Server error {status_code}")
        elif status_code >= 400:
            severity = "low"
        else:
            severity = "info"

    return classification, severity, signals
