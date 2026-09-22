from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_SCORE = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
}


@dataclass
class NormalizedFinding:
    engine: str
    title: str
    severity: str = "info"
    rule_id: str | None = None
    vuln_family: str = "other"
    cwe: str | None = None
    owasp_category: str | None = None
    message: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def risk_score(self, *, criticality: str = "medium") -> float:
        base = SEVERITY_SCORE.get((self.severity or "info").lower(), 1.0)
        weight = {"low": 0.85, "medium": 1.0, "high": 1.15}.get((criticality or "medium").lower(), 1.0)
        return round(min(10.0, base * weight), 2)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("raw", None)
        return data


def classify_family(rule_id: str | None, title: str, message: str | None = None) -> str:
    blob = f"{rule_id or ''} {title} {message or ''}".lower()
    if any(x in blob for x in ("sql", "sqli", "injection.sql")):
        return "sqli"
    if any(x in blob for x in ("xss", "cross-site-script", "html_escape", "dom-based")):
        return "xss"
    if "csrf" in blob or "cross-site-request" in blob:
        return "csrf"
    if any(x in blob for x in ("secret", "password", "api_key", "apikey", "token", "credential")):
        return "secret"
    if any(x in blob for x in ("cve-", "osv-", "dependency", "package", "ghsa-")):
        return "sca"
    return "other"


def normalize_severity(value: str | None) -> str:
    raw = (value or "info").lower()
    if raw in ("error", "critical"):
        return "critical" if raw == "critical" else "high"
    if raw in ("warning", "moderate"):
        return "medium"
    if raw in ("critical", "high", "medium", "low", "info"):
        return raw
    return "info"


def public_repo_path(path: str | None, *, repo_root: str | None = None) -> str | None:
    """Strip host scan workdirs so reports never expose /tmp/veritas-scans/... paths."""
    if not path:
        return None
    text = str(path).replace("\\", "/").strip()
    if not text:
        return None

    if repo_root:
        root = str(repo_root).replace("\\", "/").rstrip("/")
        if text == root:
            return "."
        prefix = root + "/"
        if text.startswith(prefix):
            text = text[len(prefix) :]

    marker = "/veritas-scans/"
    if marker in text:
        after = text.split(marker, 1)[1]
        # scan-id/repo/<relative>  or  scan-id/<relative>
        parts = after.split("/", 2)
        if len(parts) >= 3 and parts[1] == "repo":
            text = parts[2]
        elif len(parts) >= 2:
            text = parts[-1] if parts[1] != "repo" else "."

    while text.startswith("./"):
        text = text[2:]
    return text or None
