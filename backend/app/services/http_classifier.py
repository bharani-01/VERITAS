"""Heuristic HTTP request classification (path/query/headers metadata — no bodies)."""

from __future__ import annotations

import re
from urllib.parse import urlparse

# --- payload / path heuristics ---
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

_PATH_TRAV = re.compile(
    r"(?i)("
    r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|"
    r"/etc/passwd|/etc/shadow|boot\.ini|win\.ini|"
    r"proc/self/environ"
    r")"
)

_CMD = re.compile(
    r"(?i)("
    r";\s*(ls|cat|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b|"
    r"\|\s*(ls|cat|id|whoami|bash|sh)\b|"
    r"`[^`]+`|\$\([^)]+\)|"
    r"%0a|%0d.*(?:ls|cat|id|whoami)"
    r")"
)

_SSRF = re.compile(
    r"(?i)("
    r"(url|uri|target|dest|redirect|next|callback|feed|proxy)="
    r"[^\s&]*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|"
    r"\[::1\]|metadata\.google|169\.254\.169\.254|"
    r"file://|gopher://|dict://)"
    r")"
)

_OPEN_REDIR = re.compile(
    r"(?i)("
    r"(redirect|next|return|returnUrl|continue|url|dest|destination|goto)="
    r"[^\s&]*(?:https?%3a%2f%2f|https?://|//)(?!veritas)"
    r")"
)

_SSTI = re.compile(
    r"(?i)("
    r"\{\{.*(config|self|request|lipsum|cycler).*\}\}|"
    r"\$\{[^}]+\}|<%[=#].*%>|"
    r"__class__|__mro__|__globals__"
    r")"
)

_HEADER_INJECT = re.compile(
    r"(?i)(%0d%0a|%0a%0d|\r\n|\n|\r).*(?:Set-Cookie|Location|Content-Length)"
)

_SCANNER_UA = re.compile(
    r"(?i)("
    r"sqlmap|nikto|nmap|masscan|burp|owasp|zap|w3af|"
    r"acunetix|nessus|openvas|dirbuster|gobuster|"
    r"ffuf|wfuzz|nuclei|httpx|python-requests/lab-scanner"
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

# Families counted as "suspicious" on the Security dashboard
ATTACK_FAMILIES = (
    "sqli",
    "xss",
    "cmd_inject",
    "path_traversal",
    "ssrf",
    "ssti",
    "open_redirect",
    "header_abuse",
    "csrf",
    "scanner",
    "auth_anomaly",
    "weak_headers",
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
    "cmd_inject": [
        "Never pass user input to shell; use argv arrays / library APIs.",
        "Allow-list arguments; drop metacharacters (; | ` $).",
        "Run workers with least privilege and no shell wrappers.",
    ],
    "path_traversal": [
        "Resolve paths under a fixed root and reject .. segments.",
        "Serve files via ID lookup, not client-supplied filesystem paths.",
        "Normalize and canonical-check before open().",
    ],
    "ssrf": [
        "Allow-list outbound hostnames; block loopback, link-local, and metadata IPs.",
        "Do not fetch URLs from user input without a URL parser + network policy.",
        "Disable dangerous schemes (file, gopher, dict).",
    ],
    "ssti": [
        "Never render user strings as templates; pass data only into sandboxed engines.",
        "Disable dangerous template features / object access.",
        "Treat {{ }} / ${} patterns in input as hostile.",
    ],
    "open_redirect": [
        "Allow-list redirect targets to same-origin relative paths.",
        "Reject absolute external URLs in redirect/next parameters.",
        "Prefer post-login fixed landings over user-controlled redirects.",
    ],
    "header_abuse": [
        "Ignore untrusted X-Forwarded-* unless from a known reverse proxy.",
        "Strip CR/LF from any value reflected into response headers.",
        "Pin Host / trusted proxy config; reject spoofed forwarding headers.",
    ],
    "csrf": [
        "Require SameSite cookies and verify Origin/Referer on state-changing requests.",
        "Use anti-CSRF tokens for cookie-authenticated mutations.",
        "Prefer Authorization headers over cookies for API clients when feasible.",
    ],
    "scanner": [
        "Rate-limit and tarpit known scanner User-Agents and bursty probing.",
        "Alert on tool fingerprints (sqlmap, nikto, nuclei, etc.).",
        "Keep admin surfaces off the public internet where possible.",
    ],
    "auth_anomaly": [
        "Enforce rate limits and account lockouts on repeated auth failures.",
        "Alert on bursts of 401/403/429 from a single IP.",
        "Require MFA for admin accounts and review failed sign-in audit events.",
    ],
    "weak_headers": [
        "Send Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options.",
        "Set X-Frame-Options or CSP frame-ancestors; Referrer-Policy.",
        "Avoid exposing stack traces / Server version banners.",
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


def _missing_security_headers(response_headers: dict[str, str] | None) -> list[str]:
    if response_headers is None:
        return []
    lower = {str(k).lower(): str(v) for k, v in response_headers.items()}
    missing: list[str] = []
    checks = (
        ("strict-transport-security", "HSTS"),
        ("content-security-policy", "CSP"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-frame-options", "X-Frame-Options"),
        ("referrer-policy", "Referrer-Policy"),
    )
    for key, label in checks:
        if key == "x-frame-options":
            csp = lower.get("content-security-policy", "")
            if key in lower or "frame-ancestors" in csp.lower():
                continue
            missing.append(label)
            continue
        if key not in lower:
            missing.append(label)
    return missing


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
    user_agent: str | None = None,
    header_blob: str | None = None,
    response_headers: dict[str, str] | None = None,
) -> tuple[str, str, list[str]]:
    """
    Returns (classification, severity, signals).
    Priority: payload attacks > header abuse > csrf > scanner > auth > weak response headers > clean.
    """
    haystack = f"{path}?{query or ''}"
    headers_hay = f"{header_blob or ''}\n{user_agent or ''}"
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
    elif _CMD.search(haystack):
        classification = "cmd_inject"
        severity = "critical"
        signals.append("OS command injection pattern in path/query")
    elif _PATH_TRAV.search(haystack):
        classification = "path_traversal"
        severity = "high"
        signals.append("Path traversal / LFI pattern")
    elif _SSRF.search(haystack):
        classification = "ssrf"
        severity = "high"
        signals.append("SSRF-like URL parameter targeting internal/metadata hosts")
    elif _SSTI.search(haystack):
        classification = "ssti"
        severity = "high"
        signals.append("Server-side template injection pattern")
    elif _OPEN_REDIR.search(haystack):
        classification = "open_redirect"
        severity = "medium"
        signals.append("Open redirect pattern in redirect-like parameter")
    elif _HEADER_INJECT.search(headers_hay) or _HEADER_INJECT.search(haystack):
        classification = "header_abuse"
        severity = "high"
        signals.append("CRLF / response-splitting pattern in headers or query")
    else:
        # Spoofed forwarding / host abuse (metadata only)
        blob_l = (header_blob or "").lower()
        if "x-forwarded-host:" in blob_l or "x-original-url:" in blob_l or "x-rewrite-url:" in blob_l:
            classification = "header_abuse"
            severity = "high"
            signals.append("Suspicious forwarding / rewrite request headers")
        elif "x-forwarded-for:" in blob_l and ("127.0.0.1" in blob_l or "169.254." in blob_l):
            classification = "header_abuse"
            severity = "medium"
            signals.append("Suspicious X-Forwarded-For pointing at loopback/metadata")

    if classification == "clean":
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

    if classification == "clean" and user_agent and _SCANNER_UA.search(user_agent):
        classification = "scanner"
        severity = "medium"
        signals.append("Scanner / attack-tool User-Agent fingerprint")

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

    if classification == "clean" and 200 <= int(status_code) < 400:
        missing = _missing_security_headers(response_headers)
        # Avoid classifying every JSON API hit as weak — require several gaps.
        if len(missing) >= 3:
            classification = "weak_headers"
            severity = "low"
            signals.append("Missing security response headers: " + ", ".join(missing[:5]))

    if classification == "clean" and not signals:
        severity = "info"

    return classification, severity, signals
