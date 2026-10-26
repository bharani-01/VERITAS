Below is the **100% drop-in, zero-placeholder implementation** tailored to your exact codebase.

---

### 1. SQLAlchemy Models & Startup Schema Migration

#### 1.1 `backend/app/models/workspace.py`
Replace `backend/app/models/workspace.py` with the following (adds Phase 6A columns to `Finding` and adds `CveIntelCache` + `ScanSbomArtifact` using your exact `Mapped` / `String(36)` UUID conventions)[[2](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fmodels%2Fworkspace.py)]:

```python
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.time import utcnow
from app.models.base import Base


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    github_repo_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    github_repo_full_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    github_default_branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    github_html_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    security_level: Mapped[str] = mapped_column(String(16), default="standard")
    base_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    scan_options_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    notify_email_default: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_in_app_default: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_scan_on_push: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_scan_branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    github_webhook_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    github_webhook_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    created_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    target: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(32), default="manual")
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    security_level: Mapped[str] = mapped_column(String(16), default="standard")
    scan_mode: Mapped[str] = mapped_column(String(32), default="rules_only")
    scan_scope: Mapped[str] = mapped_column(String(16), default="full")
    ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commit_short: Mapped[str | None] = mapped_column(String(16), nullable=True)
    commit_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    commit_author: Mapped[str | None] = mapped_column(String(256), nullable=True)
    git_history_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    share_token: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True, index=True)
    progress_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    eta_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_in_app: Mapped[bool] = mapped_column(Boolean, default=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    options_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    engine: Mapped[str] = mapped_column(String(32), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    vuln_family: Mapped[str] = mapped_column(String(32), default="other", index=True)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    title: Mapped[str] = mapped_column(String(512))
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    ai_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ai_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    countermeasures_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Phase 6A: Cross-Engine Correlation & Threat Intel columns
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    matched_engines_json: Mapped[str] = mapped_column(Text, default="[]")
    engine_count: Mapped[int] = mapped_column(Integer, default=1)
    confidence_level: Mapped[str] = mapped_column(String(32), default="medium")
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_due_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    effective_priority_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CveIntelCache(Base):
    __tablename__ = "cve_intel_cache"
    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_date_added: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kev_due_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kev_ransomware_use: Mapped[str | None] = mapped_column(String(64), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ScanSbomArtifact(Base):
    __tablename__ = "scan_sbom_artifacts"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_scan_sbom_artifacts_scan_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), unique=True, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    spec_version: Mapped[str] = mapped_column(String(32), default="CycloneDX-1.5")
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    license_summary_json: Mapped[str] = mapped_column(Text, default="{}")
    policy_violations_count: Mapped[int] = mapped_column(Integer, default=0)
    sbom_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingSuppression(Base):
    __tablename__ = "finding_suppressions"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint", name="uq_project_fingerprint"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppNotification(Base):
    __tablename__ = "app_notifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(256))
    body: Mapped[str] = mapped_column(Text, default="")
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class GitHubConnection(Base):
    __tablename__ = "github_connections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), unique=True, index=True)
    github_user_id: Mapped[int] = mapped_column(Integer, index=True)
    github_login: Mapped[str] = mapped_column(String(128))
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    token_encrypted: Mapped[str] = mapped_column(Text)
    scopes: Mapped[str] = mapped_column(String(256), default="")
    needs_reauth: Mapped[bool] = mapped_column(Boolean, default=False)
    connected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
```

#### 1.2 `backend/app/models/__init__.py`
Export the two new models in `backend/app/models/__init__.py`[[16](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fmodels%2F__init__.py)]:

```python
"""SQLAlchemy ORM models."""

from app.models.base import Base
from app.models.identity import AuditEvent, AuthSession, EmailDelivery, HttpRequestEvent, OneTimeToken, User
from app.models.workspace import (
    AppNotification,
    CveIntelCache,
    Finding,
    FindingSuppression,
    GitHubConnection,
    Project,
    Scan,
    ScanSbomArtifact,
)

__all__ = [
    "Base",
    "User",
    "AuthSession",
    "OneTimeToken",
    "AuditEvent",
    "HttpRequestEvent",
    "EmailDelivery",
    "Project",
    "Scan",
    "Finding",
    "CveIntelCache",
    "ScanSbomArtifact",
    "FindingSuppression",
    "AppNotification",
    "GitHubConnection",
]
```

#### 1.3 `backend/app/services/auth.py` (`ensure_schema()` update)
In `backend/app/services/auth.py`, update the `if "findings" in tables:` block inside `ensure_schema()` so existing SQLite/PostgreSQL databases automatically gain the Phase 6A columns on startup[[8](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fauth.py)]:

```python
    if "findings" in tables:
        finding_cols = {column["name"] for column in inspector.get_columns("findings")}
        finding_alters = {
            "fingerprint": "ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64)",
            "cve_id": "ALTER TABLE findings ADD COLUMN cve_id VARCHAR(64)",
            "matched_engines_json": "ALTER TABLE findings ADD COLUMN matched_engines_json TEXT DEFAULT '[]'",
            "engine_count": "ALTER TABLE findings ADD COLUMN engine_count INTEGER DEFAULT 1",
            "confidence_level": "ALTER TABLE findings ADD COLUMN confidence_level VARCHAR(32) DEFAULT 'medium'",
            "epss_score": "ALTER TABLE findings ADD COLUMN epss_score FLOAT",
            "epss_percentile": "ALTER TABLE findings ADD COLUMN epss_percentile FLOAT",
            "is_kev": "ALTER TABLE findings ADD COLUMN is_kev BOOLEAN DEFAULT 0",
            "kev_due_date": "ALTER TABLE findings ADD COLUMN kev_due_date VARCHAR(32)",
            "effective_priority_score": "ALTER TABLE findings ADD COLUMN effective_priority_score FLOAT DEFAULT 0.0",
        }
        with db.engine.begin() as connection:
            for name, sql in finding_alters.items():
                if name not in finding_cols:
                    connection.execute(text(sql))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings (fingerprint)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_cve_id ON findings (cve_id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_is_kev ON findings (is_kev)"))
            connection.execute(
                text("CREATE INDEX IF NOT EXISTS ix_findings_effective_priority_score ON findings (effective_priority_score)")
            )
```

---

### 2. Module 1: Cross-Engine Canonical Finding Correlator (`backend/app/services/correlator.py`)

Create `backend/app/services/correlator.py`. It works directly with your `NormalizedFinding` objects (and also accepts raw `dict` objects for unit testing), merges overlapping detections across `osv`, `pip_audit`, `trivy`, `gitleaks`, `trufflehog`, `detect_secrets`, `semgrep`, `bandit`, `njsscan`, `checkov`, `hadolint`, `shellcheck`, and `openrouter_review`, and preserves constituent fingerprints so `FindingSuppression` records continue to match without regression[[5](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fscan_runner.py)][[6](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fengines%2Fnormalize.py)][[7](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fengines%2Frunners.py)]:

```python
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.services.engines.normalize import (
    NormalizedFinding,
    classify_family,
    finding_fingerprint,
    normalize_severity,
    public_repo_path,
)

CVE_REGEX = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
GHSA_REGEX = re.compile(r"\b(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.IGNORECASE)
PYSEC_REGEX = re.compile(r"\b(PYSEC-\d{4}-\d{1,6})\b", re.IGNORECASE)
CWE_REGEX = re.compile(r"\bCWE-(\d{1,5})\b", re.IGNORECASE)

SCA_ENGINES = {"osv", "osv-scanner", "osv_scanner", "pip_audit", "pip-audit", "trivy"}
SECRET_ENGINES = {"gitleaks", "trufflehog", "detect_secrets", "detect-secrets"}

SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

CONFIDENCE_RANK: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


@dataclass
class CorrelationResult:
    raw_findings_count: int
    correlated_findings_count: int
    deduplicated_count: int
    multi_engine_confirmed_count: int
    findings: list[NormalizedFinding] = field(default_factory=list)


def normalize_engine_id(engine: str | None) -> str:
    if not engine:
        return "unknown"
    e = engine.strip().lower()
    mapping = {
        "osv-scanner": "osv",
        "osv_scanner": "osv",
        "pip-audit": "pip_audit",
        "detect-secrets": "detect_secrets",
        "openrouter-review": "openrouter_review",
        "trivy-license": "trivy_license",
    }
    return mapping.get(e, e)


def _to_normalized_finding(item: NormalizedFinding | dict[str, Any]) -> NormalizedFinding:
    if isinstance(item, NormalizedFinding):
        return item
    if not isinstance(item, dict):
        raise TypeError(f"Expected NormalizedFinding or dict, got {type(item)}")

    raw_copy = dict(item.get("raw") or {})
    for k in (
        "cve_id",
        "aliases",
        "package_name",
        "package",
        "installed_version",
        "version",
        "fixed_version",
        "fix_version",
        "ecosystem",
        "confidence",
        "confidence_level",
        "verified",
        "remediation",
        "fingerprint",
    ):
        if k in item and k not in raw_copy:
            raw_copy[k] = item[k]

    engine = normalize_engine_id(item.get("engine"))
    title = str(item.get("title") or item.get("rule_id") or "Security Finding")
    rule_id = item.get("rule_id") or item.get("cve_id") or item.get("advisory_id")
    message = item.get("message") or item.get("description")
    file_path = item.get("file_path") or item.get("path")
    line_start = item.get("line_start") or item.get("line_number") or item.get("line")
    line_end = item.get("line_end") or line_start
    snippet = item.get("snippet") or item.get("code_snippet")
    cwe = item.get("cwe")
    owasp = item.get("owasp_category") or item.get("owasp")
    family = item.get("vuln_family") or item.get("category") or classify_family(rule_id, title, message)
    if family == "dependency":
        family = "sca"
    elif family == "secrets":
        family = "secret"

    return NormalizedFinding(
        engine=engine,
        title=title[:512],
        severity=normalize_severity(item.get("severity")),
        rule_id=str(rule_id)[:256] if rule_id else None,
        vuln_family=str(family),
        cwe=str(cwe)[:32] if cwe else None,
        owasp_category=str(owasp)[:64] if owasp else None,
        message=str(message) if message else None,
        file_path=public_repo_path(str(file_path)) if file_path else None,
        line_start=int(line_start) if line_start is not None else None,
        line_end=int(line_end) if line_end is not None else None,
        snippet=str(snippet) if snippet else None,
        raw=raw_copy,
    )


def extract_cve_id(nf: NormalizedFinding) -> str | None:
    raw = nf.raw if isinstance(nf.raw, dict) else {}
    candidates: list[str] = []

    for val in (
        raw.get("cve_id"),
        raw.get("VulnerabilityID"),
        raw.get("id"),
        nf.rule_id,
        nf.title,
        nf.message,
    ):
        if isinstance(val, str) and val:
            candidates.append(val)

    for alias_key in ("aliases", "Aliases"):
        aliases = raw.get(alias_key)
        if isinstance(aliases, (list, tuple, set)):
            candidates.extend(str(a) for a in aliases if a)
        elif isinstance(aliases, str):
            candidates.append(aliases)

    for text in candidates:
        m = CVE_REGEX.search(text)
        if m:
            return m.group(1).upper()
    return None


def extract_primary_advisory_id(nf: NormalizedFinding) -> str:
    cve = extract_cve_id(nf)
    if cve:
        return cve

    raw = nf.raw if isinstance(nf.raw, dict) else {}
    candidates: list[str] = []
    for val in (nf.rule_id, raw.get("id"), raw.get("VulnerabilityID"), nf.title):
        if isinstance(val, str) and val:
            candidates.append(val)
    for alias_key in ("aliases", "Aliases"):
        aliases = raw.get(alias_key)
        if isinstance(aliases, (list, tuple, set)):
            candidates.extend(str(a) for a in aliases if a)

    for text in candidates:
        m = GHSA_REGEX.search(text)
        if m:
            return m.group(1).upper()
    for text in candidates:
        m = PYSEC_REGEX.search(text)
        if m:
            return m.group(1).upper()

    return (nf.rule_id or nf.title or "UNKNOWN-ADVISORY").strip().upper()


def extract_canonical_cwe(nf: NormalizedFinding) -> str | None:
    raw = nf.raw if isinstance(nf.raw, dict) else {}
    candidates: list[str] = []
    for val in (nf.cwe, raw.get("cwe"), nf.rule_id, nf.title):
        if isinstance(val, str) and val:
            candidates.append(val)
        elif isinstance(val, list):
            candidates.extend(str(x) for x in val if x)

    for text in candidates:
        m = CWE_REGEX.search(text)
        if m:
            return f"CWE-{int(m.group(1))}"
        if text.strip().isdigit():
            return f"CWE-{int(text.strip())}"
    return None


def extract_sca_coordinates(nf: NormalizedFinding) -> tuple[str, str, str]:
    """Returns `(ecosystem, package_name_lower, installed_version_lower)`."""
    raw = nf.raw if isinstance(nf.raw, dict) else {}

    pkg_name = str(
        raw.get("package_name")
        or raw.get("PkgName")
        or raw.get("package")
        or raw.get("name")
        or (raw.get("package", {}) if isinstance(raw.get("package"), dict) else {}).get("name")
        or ""
    ).strip().lower()

    version = str(
        raw.get("installed_version")
        or raw.get("InstalledVersion")
        or raw.get("version")
        or (raw.get("package", {}) if isinstance(raw.get("package"), dict) else {}).get("version")
        or ""
    ).strip().lower()

    ecosystem = str(
        raw.get("ecosystem")
        or (raw.get("package", {}) if isinstance(raw.get("package"), dict) else {}).get("ecosystem")
        or ""
    ).strip().lower()

    # Parse from title patterns generated by run_osv / run_trivy / run_pip_audit:
    # e.g. "CVE-2026-102268 in requests 2.31.0" or "CVE-2026-102268 in requests"
    if not pkg_name or not version:
        in_match = re.search(
            r"\bin\s+([A-Za-z0-9_.\-/]+?)(?:\s+v?([0-9][A-Za-z0-9_.\-+]*))?\s*$",
            nf.title or "",
            re.IGNORECASE,
        )
        if in_match:
            if not pkg_name:
                pkg_name = in_match.group(1).strip().lower()
            if not version and in_match.group(2):
                version = in_match.group(2).strip().lower()

    if not pkg_name or not version:
        at_match = re.search(
            r"\b([A-Za-z0-9_.\-]+)@([0-9][A-Za-z0-9_.\-+]*)\b",
            f"{nf.title or ''} {nf.message or ''}",
        )
        if at_match:
            if not pkg_name:
                pkg_name = at_match.group(1).lower()
            if not version:
                version = at_match.group(2).lower()

    rel_path = (nf.file_path or "").lower()
    if not ecosystem:
        if any(rel_path.endswith(p) for p in ("requirements.txt", "poetry.lock", "pipfile.lock", "pyproject.toml")) or nf.engine == "pip_audit":
            ecosystem = "pypi"
        elif any(rel_path.endswith(p) for p in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
            ecosystem = "npm"
        elif any(rel_path.endswith(p) for p in ("go.mod", "go.sum")):
            ecosystem = "go"
        elif any(rel_path.endswith(p) for p in ("cargo.toml", "cargo.lock")):
            ecosystem = "cargo"
        else:
            ecosystem = "generic"

    return (
        ecosystem or "generic",
        pkg_name or "unknown-pkg",
        version or "any",
    )


def infer_secret_family(nf: NormalizedFinding) -> str:
    blob = f"{nf.rule_id or ''} {nf.title or ''} {nf.message or ''}".lower()
    if "aws" in blob:
        return "aws-key"
    if "github" in blob or "ghp_" in blob:
        return "github-token"
    if "slack" in blob:
        return "slack-token"
    if "stripe" in blob:
        return "stripe-key"
    if "private" in blob and "key" in blob:
        return "private-key"
    if "jwt" in blob:
        return "jwt-secret"
    return "generic-secret"


def _effective_category(nf: NormalizedFinding) -> str:
    fam = (nf.vuln_family or "").lower()
    eng = normalize_engine_id(nf.engine)
    if fam == "license" or eng == "trivy_license":
        return "license"
    if fam == "sca" or (eng in {"osv", "pip_audit"}):
        return "sca"
    if eng == "trivy" and (fam == "sca" or extract_cve_id(nf) is not None):
        return "sca"
    if fam in {"secret", "secrets"} or eng in SECRET_ENGINES:
        return "secret"
    return "sast_iac"


def build_correlation_key(nf: NormalizedFinding) -> tuple[str, ...]:
    category = _effective_category(nf)
    norm_path = (public_repo_path(nf.file_path) or "unknown").replace("\\", "/").lstrip("./").lower()
    line = int(nf.line_start or 0)

    if category == "sca":
        ecosystem, pkg_name, installed_ver = extract_sca_coordinates(nf)
        advisory_id = extract_primary_advisory_id(nf)
        # Note: osv-scanner often omits installed_version in title while pip-audit/trivy include it;
        # keying on (ecosystem, pkg_name, advisory_id) when version is 'any' ensures cross-engine merge.
        return ("sca", ecosystem, pkg_name, advisory_id)

    if category == "secret":
        snippet_clean = (nf.snippet or "").strip()
        if snippet_clean and line > 0:
            snippet_hash = hashlib.sha256(snippet_clean.encode("utf-8")).hexdigest()[:16]
            return ("secret_snippet", norm_path, str(line), snippet_hash)
        return ("secret_loc", norm_path, str(line), infer_secret_family(nf))

    if category == "license":
        ecosystem, pkg_name, installed_ver = extract_sca_coordinates(nf)
        rule = (nf.rule_id or nf.title or "license").strip().lower()
        return ("license", ecosystem, pkg_name, installed_ver, rule)

    # SAST & IaC: group by (normalized_rel_file_path, line_bucket, canonical_cwe_id)
    cwe = extract_canonical_cwe(nf)
    if cwe and line > 0:
        line_bucket = line // 3
        return ("sast_cwe", norm_path, str(line_bucket), cwe)

    return (
        "sast_rule",
        normalize_engine_id(nf.engine),
        norm_path,
        str(line),
        (nf.rule_id or nf.title or "").strip().lower()[:120],
    )


def _merge_group(
    corr_key: tuple[str, ...],
    group: list[NormalizedFinding],
    suppressed_fingerprints: set[str],
) -> NormalizedFinding:
    sorted_group = sorted(
        group,
        key=lambda item: (
            SEVERITY_RANK.get(normalize_severity(item.severity), 0),
            len(item.message or ""),
        ),
        reverse=True,
    )
    primary = sorted_group[0]

    matched_engines = sorted({normalize_engine_id(item.engine) for item in group if item.engine})
    if not matched_engines:
        matched_engines = ["unknown"]
    engine_count = len(matched_engines)

    best_severity = max(
        (normalize_severity(item.severity) for item in group),
        key=lambda s: SEVERITY_RANK.get(s, 0),
    )

    best_message = max(
        ((item.message or "").strip() for item in group),
        key=len,
        default="",
    )

    # Merge remediation / fixed versions across engines
    fix_versions: set[str] = set()
    remediations: list[str] = []
    for item in sorted_group:
        raw_d = item.raw if isinstance(item.raw, dict) else {}
        for f_key in ("fixed_version", "fix_version", "FixedVersion"):
            fv = raw_d.get(f_key)
            if isinstance(fv, str) and fv.strip():
                fix_versions.add(fv.strip())
        for fv_list_key in ("fix_versions", "fixed_versions"):
            fvl = raw_d.get(fv_list_key)
            if isinstance(fvl, list):
                fix_versions.update(str(v).strip() for v in fvl if v)
        rem = raw_d.get("remediation")
        if isinstance(rem, str) and rem.strip() and rem.strip() not in remediations:
            remediations.append(rem.strip())

    combined_message = best_message or primary.message or primary.title
    if remediations:
        rem_text = " ".join(remediations)
        if rem_text not in combined_message:
            combined_message = f"{combined_message} {rem_text}".strip()
    if fix_versions:
        fix_str = f"Fixed in: {', '.join(sorted(fix_versions))}."
        if fix_str not in combined_message:
            combined_message = f"{combined_message} {fix_str}".strip()

    cve_id = next((extract_cve_id(item) for item in sorted_group if extract_cve_id(item)), None)
    cwe_id = next((extract_canonical_cwe(item) for item in sorted_group if extract_canonical_cwe(item)), primary.cwe)

    # Confidence calculation
    verified_secret = any(
        normalize_engine_id(item.engine) == "trufflehog"
        and (
            bool((item.raw or {}).get("Verified"))
            or bool((item.raw or {}).get("verified"))
            or "(verified)" in (item.title or "").lower()
        )
        for item in group
    )
    if engine_count >= 2 or verified_secret:
        confidence_level = "high"
    else:
        raw_conf = str((primary.raw or {}).get("confidence_level") or (primary.raw or {}).get("confidence") or "medium").lower()
        confidence_level = raw_conf if raw_conf in ("high", "medium", "low") else "medium"

    # Collect constituent raw fingerprints so existing FindingSuppression rows never regress
    constituent_fps: set[str] = set()
    for item in group:
        explicit_fp = (item.raw or {}).get("fingerprint") if isinstance(item.raw, dict) else None
        if isinstance(explicit_fp, str) and explicit_fp.strip():
            constituent_fps.add(explicit_fp.strip())
        constituent_fps.add(item.fingerprint())

    canonical_fp = finding_fingerprint(
        engine=matched_engines[0] if engine_count == 1 else "correlated",
        rule_id=cve_id or primary.rule_id or corr_key[-1],
        file_path=primary.file_path,
        line_start=primary.line_start,
        title=primary.title,
    )

    # Preserve single-engine fingerprint for 100% backward compatibility with existing tests
    if engine_count == 1:
        explicit_fp = (primary.raw or {}).get("fingerprint") if isinstance(primary.raw, dict) else None
        chosen_fp = str(explicit_fp) if explicit_fp else primary.fingerprint()
    else:
        chosen_fp = canonical_fp

    matched_suppressed_fp = next(
        (fp for fp in (constituent_fps | {canonical_fp, chosen_fp}) if fp in suppressed_fingerprints),
        None,
    )
    if matched_suppressed_fp:
        chosen_fp = matched_suppressed_fp

    merged_raw = dict(primary.raw or {})
    merged_raw.update(
        {
            "cve_id": cve_id,
            "matched_engines": matched_engines,
            "matched_engines_json": json.dumps(matched_engines),
            "engine_count": engine_count,
            "confidence_level": confidence_level,
            "canonical_fingerprint": chosen_fp,
            "constituent_fingerprints": sorted(constituent_fps | {canonical_fp}),
            "is_suppressed": matched_suppressed_fp is not None,
        }
    )

    merged = NormalizedFinding(
        engine=matched_engines[0],
        title=primary.title,
        severity=best_severity,
        rule_id=cve_id or primary.rule_id,
        vuln_family="sca" if corr_key[0] == "sca" else ("secret" if corr_key[0].startswith("secret") else primary.vuln_family),
        cwe=cwe_id,
        owasp_category=primary.owasp_category,
        message=combined_message[:2000] if combined_message else None,
        file_path=primary.file_path,
        line_start=primary.line_start,
        line_end=primary.line_end,
        snippet=primary.snippet,
        raw=merged_raw,
    )
    return merged


def correlate_findings(
    raw_findings: list[NormalizedFinding | dict[str, Any]],
    suppressed_fingerprints: set[str] | None = None,
) -> CorrelationResult:
    """
    Deduplicates and correlates findings across all VERITAS engines.
    Returns a `CorrelationResult` containing canonical `NormalizedFinding` objects.
    """
    suppressed = suppressed_fingerprints or set()
    normalized_list = [_to_normalized_finding(item) for item in raw_findings]

    buckets: dict[tuple[str, ...], list[NormalizedFinding]] = {}
    for nf in normalized_list:
        key = build_correlation_key(nf)
        buckets.setdefault(key, []).append(nf)

    correlated: list[NormalizedFinding] = []
    multi_engine_count = 0

    for corr_key, group in buckets.items():
        merged = _merge_group(corr_key, group, suppressed)
        if int((merged.raw or {}).get("engine_count") or 1) >= 2:
            multi_engine_count += 1
        correlated.append(merged)

    return CorrelationResult(
        raw_findings_count=len(normalized_list),
        correlated_findings_count=len(correlated),
        deduplicated_count=max(0, len(normalized_list) - len(correlated)),
        multi_engine_confirmed_count=multi_engine_count,
        findings=correlated,
    )
```

---

### 3. Module 2: Offline CISA KEV + FIRST EPSS Threat Intelligence (`backend/app/services/threat_intel.py`)

Create `backend/app/services/threat_intel.py` using `httpx` (already in your `backend/requirements.txt`) and your `app.core.time.utcnow` / `ensure_utc` helpers[[4](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fapi%2Fadmin.py)][[9](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fai_report.py)]:

```python
from __future__ import annotations

import csv
import gzip
import io
import logging
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import APP_ENV
from app.core.time import ensure_utc, utcnow
from app.models.workspace import CveIntelCache
from app.services.correlator import extract_cve_id
from app.services.engines.normalize import NormalizedFinding, normalize_severity

logger = logging.getLogger(__name__)

CISA_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"
FIRST_EPSS_BULK_CSV_GZ_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

SEVERITY_BASE_SCORE: dict[str, float] = {
    "critical": 7.0,
    "high": 5.0,
    "medium": 3.0,
    "low": 1.5,
    "info": 0.5,
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def compute_effective_priority_score(
    *,
    severity: str | None,
    is_kev: bool = False,
    epss_score: float | None = None,
    engine_count: int = 1,
) -> float:
    """
    Composite Priority Formula on a 0.0-10.0 scale:
      - Base score by severity: critical = 7.0, high = 5.0, medium = 3.0, low = 1.5, info = 0.5
      - If is_kev is True: severity floor promoted to critical (7.0) and add +2.5
      - Add min(1.5, (epss_score or 0.0) * 2.0) for exploit probability
      - If engine_count >= 2: add +0.5 for multi-engine confirmation
      - Clamp to [0.0, 10.0] rounded to 2 decimal places
    """
    effective_sev = "critical" if is_kev else normalize_severity(severity)
    base = SEVERITY_BASE_SCORE.get(effective_sev, 3.0)
    kev_bonus = 2.5 if is_kev else 0.0
    epss_bonus = min(1.5, max(0.0, float(epss_score or 0.0)) * 2.0)
    multi_engine_bonus = 0.5 if int(engine_count or 1) >= 2 else 0.0
    return round(min(10.0, max(0.0, base + kev_bonus + epss_bonus + multi_engine_bonus)), 2)


def sync_cisa_kev_feed(db: Session, *, timeout: float = 15.0) -> int:
    """
    Fetches the public CISA KEV catalog and upserts rows into `CveIntelCache`.
    Fail-open: logs a warning and returns 0 on any network or parsing error.
    """
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(CISA_KEV_FEED_URL)
            resp.raise_for_status()
            payload = resp.json()
    except Exception as exc:
        logger.warning("CISA KEV sync failed (fail-open): %s", str(exc)[:240])
        return 0

    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        return 0

    now = utcnow()
    existing_rows = {
        row.cve_id: row for row in db.scalars(select(CveIntelCache)).all()
    }
    upserted = 0

    for item in vulns:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        row = existing_rows.get(cve_id)
        if row is None:
            row = CveIntelCache(cve_id=cve_id)
            db.add(row)
            existing_rows[cve_id] = row

        row.is_kev = True
        row.kev_vendor = str(item.get("vendorProject") or "")[:255] or None
        row.kev_product = str(item.get("product") or "")[:255] or None
        row.kev_date_added = str(item.get("dateAdded") or "")[:32] or None
        row.kev_due_date = str(item.get("dueDate") or "")[:32] or None
        row.kev_ransomware_use = str(item.get("knownRansomwareCampaignUse") or "")[:64] or None
        row.updated_at = now
        upserted += 1

    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("CISA KEV commit failed: %s", str(exc)[:200])
        return 0

    return upserted


def sync_epss_batch(db: Session, cve_ids: list[str], *, timeout: float = 5.0) -> int:
    """
    Queries FIRST EPSS API in batches of up to 100 CVEs and upserts `epss_score`
    and `epss_percentile` into `CveIntelCache`. Fail-open on any network failure.
    """
    clean_cves = sorted(
        {c.strip().upper() for c in cve_ids if isinstance(c, str) and c.strip().upper().startswith("CVE-")}
    )
    if not clean_cves:
        return 0

    now = utcnow()
    upserted = 0

    for idx in range(0, len(clean_cves), 100):
        chunk = clean_cves[idx : idx + 100]
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(FIRST_EPSS_API_URL, params={"cve": ",".join(chunk)})
                resp.raise_for_status()
                body = resp.json()
        except Exception as exc:
            logger.warning("FIRST EPSS batch sync failed (fail-open): %s", str(exc)[:240])
            continue

        data_rows = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data_rows, list):
            continue

        existing_map = {
            row.cve_id: row
            for row in db.scalars(select(CveIntelCache).where(CveIntelCache.cve_id.in_(chunk))).all()
        }

        for item in data_rows:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            try:
                epss_val = float(item["epss"]) if item.get("epss") is not None else None
                pct_val = float(item["percentile"]) if item.get("percentile") is not None else None
            except (TypeError, ValueError):
                continue

            row = existing_map.get(cve_id)
            if row is None:
                row = CveIntelCache(cve_id=cve_id, is_kev=False)
                db.add(row)
                existing_map[cve_id] = row

            row.epss_score = epss_val
            row.epss_percentile = pct_val
            row.updated_at = now
            upserted += 1

    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("FIRST EPSS batch commit failed: %s", str(exc)[:200])
        return 0

    return upserted


def sync_epss_bulk_stream(db: Session, *, timeout: float = 15.0) -> int:
    """
    Streams `epss_scores-current.csv.gz` and updates EPSS scores for cached CVEs.
    Falls back to `sync_epss_batch` if the gzip stream fails.
    """
    cached = {row.cve_id: row for row in db.scalars(select(CveIntelCache)).all()}
    if not cached:
        return 0

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(FIRST_EPSS_BULK_CSV_GZ_URL)
            resp.raise_for_status()
            raw_gz = resp.content

        now = utcnow()
        updated = 0
        with gzip.GzipFile(fileobj=io.BytesIO(raw_gz), mode="rb") as gz:
            text_stream = io.TextIOWrapper(gz, encoding="utf-8", errors="replace")
            reader = csv.reader(line for line in text_stream if line and not line.startswith("#"))
            _header = next(reader, None)
            for parts in reader:
                if len(parts) < 3:
                    continue
                cve_id = parts[0].strip().upper()
                row = cached.get(cve_id)
                if row is None:
                    continue
                try:
                    row.epss_score = float(parts[1])
                    row.epss_percentile = float(parts[2])
                    row.updated_at = now
                    updated += 1
                except ValueError:
                    continue
        db.commit()
        return updated
    except Exception as exc:
        logger.info("Bulk EPSS stream skipped (%s); falling back to batch API.", str(exc)[:200])
        return sync_epss_batch(db, list(cached.keys()), timeout=timeout)


def get_threat_intel_status(db: Session) -> dict[str, Any]:
    total_cached = db.scalar(select(func.count()).select_from(CveIntelCache)) or 0
    total_kev = (
        db.scalar(select(func.count()).select_from(CveIntelCache).where(CveIntelCache.is_kev.is_(True)))
        or 0
    )
    last_dt = db.scalar(select(func.max(CveIntelCache.updated_at)))
    return {
        "total_cached_cves": int(total_cached),
        "total_kev_cves": int(total_kev),
        "last_synced_at": ensure_utc(last_dt) if last_dt else None,
    }


def sync_threat_intel_feeds(
    db: Session,
    *,
    cve_ids: list[str] | None = None,
    include_bulk_epss: bool = False,
) -> dict[str, Any]:
    """
    Synchronizes CISA KEV + FIRST EPSS into `CveIntelCache`.
    Strictly fail-open: never raises unhandled exceptions.
    """
    kev_upserted = sync_cisa_kev_feed(db, timeout=15.0)
    epss_upserted = 0

    if cve_ids:
        epss_upserted += sync_epss_batch(db, cve_ids, timeout=5.0)
    elif include_bulk_epss:
        epss_upserted += sync_epss_bulk_stream(db, timeout=15.0)
    else:
        missing_epss_kev = list(
            db.scalars(
                select(CveIntelCache.cve_id)
                .where(CveIntelCache.is_kev.is_(True), CveIntelCache.epss_score.is_(None))
                .limit(200)
            ).all()
        )
        if missing_epss_kev:
            epss_upserted += sync_epss_batch(db, missing_epss_kev, timeout=5.0)

    status = get_threat_intel_status(db)
    status["kev_upserted"] = kev_upserted
    status["epss_upserted"] = epss_upserted
    return status


def enrich_findings_with_intel(
    db: Session,
    findings: list[NormalizedFinding],
    *,
    allow_network: bool | None = None,
) -> list[NormalizedFinding]:
    """
    Enriches correlated `NormalizedFinding` objects with `CveIntelCache` metadata,
    promotes KEV findings to `critical` severity, computes `effective_priority_score`,
    and sorts findings by `effective_priority_score DESC`.
    """
    if not findings:
        return []

    if allow_network is None:
        allow_network = APP_ENV != "test"

    now = utcnow()
    stale_cutoff = now - timedelta(hours=24)

    distinct_cves: set[str] = set()
    for nf in findings:
        if not isinstance(nf.raw, dict):
            nf.raw = {}
        cve = nf.raw.get("cve_id") or extract_cve_id(nf)
        if isinstance(cve, str) and cve.upper().startswith("CVE-"):
            norm_cve = cve.upper()
            nf.raw["cve_id"] = norm_cve
            distinct_cves.add(norm_cve)

    cache_map: dict[str, CveIntelCache] = {}
    if distinct_cves:
        rows = list(
            db.scalars(
                select(CveIntelCache).where(CveIntelCache.cve_id.in_(sorted(distinct_cves)))
            ).all()
        )
        cache_map = {row.cve_id: row for row in rows}

        if allow_network:
            # If cache is completely empty, do a fast KEV sync first
            total_cached = db.scalar(select(func.count()).select_from(CveIntelCache)) or 0
            if total_cached == 0:
                sync_cisa_kev_feed(db, timeout=10.0)
                rows = list(
                    db.scalars(
                        select(CveIntelCache).where(CveIntelCache.cve_id.in_(sorted(distinct_cves)))
                    ).all()
                )
                cache_map = {row.cve_id: row for row in rows}

            missing_or_stale = [
                cve
                for cve in sorted(distinct_cves)
                if cve not in cache_map
                or cache_map[cve].epss_score is None
                or (
                    cache_map[cve].updated_at is not None
                    and ensure_utc(cache_map[cve].updated_at) < stale_cutoff
                )
            ]
            if missing_or_stale:
                sync_epss_batch(db, missing_or_stale, timeout=5.0)
                rows = list(
                    db.scalars(
                        select(CveIntelCache).where(CveIntelCache.cve_id.in_(sorted(distinct_cves)))
                    ).all()
                )
                cache_map = {row.cve_id: row for row in rows}

    for nf in findings:
        raw = nf.raw if isinstance(nf.raw, dict) else {}
        cve_id = raw.get("cve_id")
        intel = cache_map.get(cve_id) if cve_id else None

        is_kev = bool(raw.get("is_kev")) or (bool(intel.is_kev) if intel else False)
        kev_due_date = raw.get("kev_due_date") or (intel.kev_due_date if intel else None)
        epss_score = (
            float(intel.epss_score)
            if (intel and intel.epss_score is not None)
            else (float(raw["epss_score"]) if raw.get("epss_score") is not None else None)
        )
        epss_percentile = (
            float(intel.epss_percentile)
            if (intel and intel.epss_percentile is not None)
            else (float(raw["epss_percentile"]) if raw.get("epss_percentile") is not None else None)
        )

        if is_kev:
            nf.severity = "critical"
            raw["confidence_level"] = "high"

        engine_count = int(raw.get("engine_count") or 1)
        priority = compute_effective_priority_score(
            severity=nf.severity,
            is_kev=is_kev,
            epss_score=epss_score,
            engine_count=engine_count,
        )

        raw["is_kev"] = is_kev
        raw["kev_due_date"] = kev_due_date
        raw["epss_score"] = epss_score
        raw["epss_percentile"] = epss_percentile
        raw["effective_priority_score"] = priority
        nf.raw = raw

    findings.sort(
        key=lambda item: (
            float((item.raw or {}).get("effective_priority_score") or 0.0),
            1 if (item.raw or {}).get("is_kev") else 0,
            SEVERITY_RANK.get(normalize_severity(item.severity), 0),
            float((item.raw or {}).get("epss_score") or 0.0),
        ),
        reverse=True,
    )
    return findings
```

---

### 4. Module 3: Trivy CycloneDX SBOM & License Governance (`backend/app/services/engines/trivy_sbom.py`)

Create `backend/app/services/engines/trivy_sbom.py`:

```python
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.time import utcnow
from app.models.workspace import ScanSbomArtifact
from app.services.engines.normalize import NormalizedFinding

logger = logging.getLogger(__name__)

PERMISSIVE_LICENSES = (
    "MIT",
    "APACHE-2.0",
    "APACHE-1.1",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "BSD-4-CLAUSE",
    "ISC",
    "0BSD",
    "UNLICENSE",
    "PYTHON-2.0",
    "PSF-2.0",
    "ZLIB",
    "CC0-1.0",
)

WEAK_COPYLEFT_LICENSES = (
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "MPL-2.0",
    "MPL-1.1",
    "EPL-1.0",
    "EPL-2.0",
    "CDDL-1.0",
    "CDDL-1.1",
)

RESTRICTED_COPYLEFT_LICENSES = (
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-1.0",
    "AGPL-3.0",
    "SSPL-1.0",
    "EUPL-1.2",
    "OSL-3.0",
)


@dataclass
class SbomAnalysisResult:
    spec_version: str
    component_count: int
    policy_violations_count: int
    license_summary: dict[str, Any]
    components: list[dict[str, Any]]
    sbom_dict: dict[str, Any]
    sbom_json: str
    findings: list[NormalizedFinding] = field(default_factory=list)


def classify_license(license_id: str | None) -> str:
    if not license_id or not license_id.strip():
        return "unknown"
    norm = license_id.strip().upper()
    if norm in ("UNKNOWN", "NONE", "NOASSERTION"):
        return "unknown"

    # Check weak copyleft before restricted copyleft so LGPL is never misclassified as GPL
    for prefix in WEAK_COPYLEFT_LICENSES:
        if norm.startswith(prefix) or f" {prefix}" in norm:
            return "weak_copyleft"
    if "LESSER GENERAL PUBLIC" in norm or "MOZILLA PUBLIC" in norm:
        return "weak_copyleft"

    for prefix in RESTRICTED_COPYLEFT_LICENSES:
        if norm.startswith(prefix) or f" {prefix}" in norm:
            return "restricted_copyleft"
    if any(k in norm for k in ("AGPL", "SSPL", "GPL-", "GNU GENERAL PUBLIC", "AFFERO GENERAL PUBLIC")):
        return "restricted_copyleft"

    for prefix in PERMISSIVE_LICENSES:
        if norm.startswith(prefix) or f" {prefix}" in norm:
            return "permissive"
    if any(k in norm for k in ("MIT LICENSE", "APACHE LICENSE", "BSD LICENSE", "ISC LICENSE")):
        return "permissive"

    return "unknown"


def _fallback_manifest_cyclonedx(workdir: Path) -> dict[str, Any]:
    """
    Deterministic manifest parser (`requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`)
    that emits a valid CycloneDX 1.5 JSON structure when `trivy` is not installed or exits non-zero.
    """
    components: list[dict[str, Any]] = []
    seen_purls: set[str] = set()

    custom_license_map: dict[str, str] = {}
    lic_file = workdir / "veritas-licenses.json"
    if lic_file.is_file():
        try:
            parsed_map = json.loads(lic_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(parsed_map, dict):
                custom_license_map = {str(k).lower(): str(v) for k, v in parsed_map.items() if v}
        except Exception:
            pass

    def _add_comp(
        name: str,
        version: str,
        ecosystem: str,
        purl: str,
        license_id: str | None,
        rel_file: str,
    ) -> None:
        if purl in seen_purls:
            return
        seen_purls.add(purl)
        resolved_lic = license_id or custom_license_map.get(name.lower())
        licenses_arr = [{"license": {"id": resolved_lic}}] if resolved_lic else []
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "licenses": licenses_arr,
                "properties": [
                    {"name": "aquasecurity:trivy:PkgType", "value": ecosystem},
                    {"name": "veritas:source_file", "value": rel_file},
                ],
            }
        )

    # 1. requirements*.txt
    for req in sorted(workdir.rglob("*requirements*.txt")):
        if any(p in req.parts for p in (".git", "node_modules", ".venv", "venv")):
            continue
        rel = str(req.relative_to(workdir)).replace("\\", "/")
        for raw_line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            inline_lic: str | None = None
            if "#" in line:
                line, comment = line.split("#", 1)
                line = line.strip()
                m_lic = re.search(r"license\s*[:=]\s*([A-Za-z0-9.\-+]+)", comment, re.I)
                if m_lic:
                    inline_lic = m_lic.group(1).strip()
            m_pkg = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=|<=|>|<)\s*([A-Za-z0-9_.\-+]+)", line)
            if m_pkg:
                pkg_name, pkg_ver = m_pkg.group(1), m_pkg.group(2)
            else:
                pkg_name = re.split(r"[;\[\s]", line)[0].strip()
                pkg_ver = "0.0.0"
            if pkg_name:
                purl = f"pkg:pypi/{pkg_name.lower()}@{pkg_ver}"
                _add_comp(pkg_name, pkg_ver, "pypi", purl, inline_lic, rel)

    # 2. package.json
    for pkg_json in sorted(workdir.rglob("package.json")):
        if any(p in pkg_json.parts for p in (".git", "node_modules", ".venv", "venv")):
            continue
        rel = str(pkg_json.relative_to(workdir)).replace("\\", "/")
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        lic_policies = data.get("licensePolicies") or data.get("licensesMap") or {}
        for sec in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(sec)
            if not isinstance(deps, dict):
                continue
            for dep_name, spec in deps.items():
                if isinstance(spec, dict):
                    ver = str(spec.get("version") or "0.0.0").lstrip("^~>=< ")
                    lic = str(spec.get("license") or "").strip() or None
                else:
                    ver = str(spec or "0.0.0").lstrip("^~>=< ") or "0.0.0"
                    lic = lic_policies.get(dep_name) if isinstance(lic_policies, dict) else None
                purl = f"pkg:npm/{dep_name}@{ver}"
                _add_comp(dep_name, ver, "npm", purl, lic, rel)

    # 3. pyproject.toml
    for pyproj in sorted(workdir.rglob("pyproject.toml")):
        if any(p in pyproj.parts for p in (".git", "node_modules", ".venv", "venv")):
            continue
        rel = str(pyproj.relative_to(workdir)).replace("\\", "/")
        text = pyproj.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=|<=)\s*([0-9][A-Za-z0-9_.\-]*)"', text):
            pkg_name, pkg_ver = m.group(1), m.group(2)
            purl = f"pkg:pypi/{pkg_name.lower()}@{pkg_ver}"
            _add_comp(pkg_name, pkg_ver, "pypi", purl, None, rel)

    # 4. go.mod
    for gomod in sorted(workdir.rglob("go.mod")):
        if ".git" in gomod.parts:
            continue
        rel = str(gomod.relative_to(workdir)).replace("\\", "/")
        for raw_line in gomod.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("module ", "go ", "//", "require", ")")):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                purl = f"pkg:golang/{parts[0]}@{parts[1]}"
                _add_comp(parts[0], parts[1], "golang", purl, None, rel)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": utcnow().isoformat(),
            "tools": [{"vendor": "VERITAS", "name": "veritas-sbom", "version": "0.6.0"}],
        },
        "components": components,
    }


def analyze_cyclonedx_sbom(sbom_data: dict[str, Any]) -> SbomAnalysisResult:
    raw_spec = str(sbom_data.get("specVersion") or "1.5")
    spec_version = f"CycloneDX-{raw_spec}" if not raw_spec.startswith("CycloneDX") else raw_spec

    raw_components = sbom_data.get("components")
    if not isinstance(raw_components, list):
        raw_components = []

    counts = {
        "permissive": 0,
        "weak_copyleft": 0,
        "restricted_copyleft": 0,
        "unknown": 0,
    }
    by_license: dict[str, int] = {}
    parsed_components: list[dict[str, Any]] = []
    findings: list[NormalizedFinding] = []
    violations = 0

    tier_rank = {
        "restricted_copyleft": 4,
        "weak_copyleft": 3,
        "unknown": 2,
        "permissive": 1,
    }

    for comp in raw_components:
        if not isinstance(comp, dict):
            continue
        if comp.get("type") == "application" and not comp.get("purl"):
            continue

        name = str(comp.get("name") or "unknown").strip()
        version = str(comp.get("version") or "0.0.0").strip()
        purl = str(comp.get("purl") or f"pkg:generic/{name}@{version}").strip()

        ecosystem = "generic"
        if purl.startswith("pkg:"):
            ecosystem = purl[4:].split("/", 1)[0].lower() or "generic"
        source_file = "SBOM"
        for prop in comp.get("properties") or []:
            if isinstance(prop, dict):
                if prop.get("name") == "aquasecurity:trivy:PkgType" and prop.get("value"):
                    ecosystem = str(prop["value"]).lower()
                elif prop.get("name") in ("veritas:source_file", "aquasecurity:trivy:FilePath") and prop.get("value"):
                    source_file = str(prop["value"])

        licenses: list[str] = []
        for entry in comp.get("licenses") or []:
            if isinstance(entry, dict):
                lic_obj = entry.get("license")
                if isinstance(lic_obj, dict):
                    lid = lic_obj.get("id") or lic_obj.get("name")
                    if isinstance(lid, str) and lid.strip():
                        licenses.append(lid.strip())
                elif isinstance(entry.get("expression"), str) and entry["expression"].strip():
                    licenses.append(entry["expression"].strip())
            elif isinstance(entry, str) and entry.strip():
                licenses.append(entry.strip())

        if not licenses:
            risk_tier = "unknown"
            by_license["UNKNOWN"] = by_license.get("UNKNOWN", 0) + 1
        else:
            tiers = [classify_license(lic) for lic in licenses]
            risk_tier = max(tiers, key=lambda t: tier_rank.get(t, 0))
            for lic in licenses:
                by_license[lic] = by_license.get(lic, 0) + 1

        counts[risk_tier] = counts.get(risk_tier, 0) + 1
        parsed_components.append(
            {
                "name": name,
                "version": version,
                "purl": purl,
                "ecosystem": ecosystem,
                "licenses": licenses if licenses else ["UNKNOWN"],
                "risk_tier": risk_tier,
                "source_file": source_file,
            }
        )

        if risk_tier == "restricted_copyleft":
            violations += 1
            restricted_lics = [lic for lic in licenses if classify_license(lic) == "restricted_copyleft"] or licenses
            lic_str = ", ".join(restricted_lics)
            findings.append(
                NormalizedFinding(
                    engine="trivy_license",
                    title=f"Restricted Copyleft License Detected: {name}@{version} ({lic_str})"[:512],
                    severity="high",
                    rule_id=f"LICENSE-{restricted_lics[0].upper()}"[:120],
                    vuln_family="license",
                    cwe="CWE-1104",
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    message=(
                        f"Package {name}@{version} ({ecosystem}) is licensed under {lic_str}, "
                        f"a restricted copyleft license that may impose source disclosure obligations."
                    ),
                    file_path=source_file,
                    line_start=1,
                    line_end=1,
                    raw={
                        "package_name": name,
                        "installed_version": version,
                        "ecosystem": ecosystem,
                        "licenses": restricted_lics,
                        "confidence_level": "high",
                    },
                )
            )

    summary = {
        "permissive": counts["permissive"],
        "weak_copyleft": counts["weak_copyleft"],
        "restricted_copyleft": counts["restricted_copyleft"],
        "unknown": counts["unknown"],
        "by_license": dict(sorted(by_license.items(), key=lambda kv: (-kv[1], kv[0]))),
    }

    return SbomAnalysisResult(
        spec_version=spec_version,
        component_count=len(parsed_components),
        policy_violations_count=violations,
        license_summary=summary,
        components=parsed_components,
        sbom_dict=sbom_data,
        sbom_json=json.dumps(sbom_data, indent=2),
        findings=findings,
    )


def run_trivy_sbom(
    db: Session,
    *,
    scan_id: str,
    project_id: str,
    workdir: Path | None,
) -> tuple[SbomAnalysisResult, dict[str, Any]]:
    """
    Executes Trivy CycloneDX SBOM generation on `workdir` (or falls back to the deterministic
    manifest parser when `trivy` is unavailable or `workdir` has no Trivy binary),
    persists `ScanSbomArtifact`, and returns `(SbomAnalysisResult, engine_meta)`.
    """
    meta: dict[str, Any] = {"engine": "trivy_sbom", "available": False}
    sbom_data: dict[str, Any] | None = None

    if workdir and workdir.exists():
        trivy_bin = shutil.which("trivy")
        if trivy_bin:
            meta["available"] = True
            fd, tmp_path = tempfile.mkstemp(prefix=f"veritas-sbom-{scan_id[:8]}-", suffix=".cdx.json")
            os.close(fd)
            try:
                proc = subprocess.run(
                    [
                        trivy_bin,
                        "fs",
                        "--format",
                        "cyclonedx",
                        "--scanners",
                        "license",
                        "--quiet",
                        "--output",
                        tmp_path,
                        str(workdir),
                    ],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=180,
                    check=False,
                )
                meta["returncode"] = proc.returncode
                if proc.returncode == 0 and os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 2:
                    loaded = json.loads(Path(tmp_path).read_text(encoding="utf-8", errors="replace"))
                    if isinstance(loaded, dict) and loaded.get("bomFormat") == "CycloneDX":
                        sbom_data = loaded
                        meta["mode"] = "trivy-cli"
            except Exception as exc:
                logger.warning("Trivy SBOM CLI failed, using manifest parser fallback: %s", str(exc)[:200])
            finally:
                Path(tmp_path).unlink(missing_ok=True)

        if sbom_data is None:
            sbom_data = _fallback_manifest_cyclonedx(workdir)
            meta["available"] = True
            meta["mode"] = "manifest-fallback"
    else:
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {"timestamp": utcnow().isoformat()},
            "components": [],
        }
        meta["skipped"] = "no repository workspace"

    result = analyze_cyclonedx_sbom(sbom_data)
    meta["components"] = result.component_count
    meta["policy_violations"] = result.policy_violations_count
    meta["findings"] = len(result.findings)

    existing = db.scalar(select(ScanSbomArtifact).where(ScanSbomArtifact.scan_id == scan_id))
    if existing is None:
        artifact = ScanSbomArtifact(
            scan_id=scan_id,
            project_id=project_id,
            spec_version=result.spec_version,
            component_count=result.component_count,
            license_summary_json=json.dumps(result.license_summary),
            policy_violations_count=result.policy_violations_count,
            sbom_json=result.sbom_json,
        )
        db.add(artifact)
    else:
        existing.spec_version = result.spec_version
        existing.component_count = result.component_count
        existing.license_summary_json = json.dumps(result.license_summary)
        existing.policy_violations_count = result.policy_violations_count
        existing.sbom_json = result.sbom_json
        db.add(existing)

    db.commit()
    return result, meta
```

---

### 5. Exact Updates to `ai_report.py`, `scan_runner.py`, `projects.py`, `workspace.py`, and `admin.py`

#### 5.1 `backend/app/services/ai_report.py`
Update `generate_final_report` in `backend/app/services/ai_report.py` so it accepts optional `intel_summary: dict | None = None` and prioritizes CISA KEV + EPSS findings in the Groq Executive Summary[[9](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fai_report.py)]:

```python
"""Groq final AI report + countermeasures (fail-open)."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from app.core.config import GROQ_API_KEY, GROQ_MODEL, reload_env
from app.services.engines.normalize import NormalizedFinding

logger = logging.getLogger(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_MAX_FINDINGS = 40
_TIMEOUT = 90.0


def _api_key() -> str:
    reload_env()
    return (os.getenv("GROQ_API_KEY") or os.getenv("AI_API_KEY") or GROQ_API_KEY or "").strip()


def _model() -> str:
    reload_env()
    return (os.getenv("GROQ_REPORT_MODEL") or os.getenv("GROQ_MODEL") or GROQ_MODEL or "openai/gpt-oss-120b").strip()


def generate_final_report(
    findings: list[NormalizedFinding],
    *,
    project_name: str,
    target: str,
    intel_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return {status, report_markdown, countermeasures_by_index}. Never raises."""
    key = _api_key()
    if not key:
        return {"status": "skipped_no_key", "report_markdown": None, "countermeasures": {}}

    ranked = sorted(
        findings,
        key=lambda f: (
            1 if (f.raw or {}).get("is_kev") else 0,
            float((f.raw or {}).get("effective_priority_score") or 0.0),
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((f.severity or "").lower(), 0),
        ),
        reverse=True,
    )[:_MAX_FINDINGS]

    if not ranked:
        md = (
            f"# VERITAS security summary\n\n"
            f"**Project:** {project_name}\n**Target:** {target}\n\n"
            f"No findings were reported by the scan engines.\n"
        )
        return {"status": "ok_empty", "report_markdown", md, "countermeasures": {}, "model": _model()}

    payload = []
    for i, f in enumerate(ranked):
        raw_meta = f.raw if isinstance(f.raw, dict) else {}
        payload.append(
            {
                "i": i,
                "title": (f.title or "")[:200],
                "severity": f.severity,
                "family": f.vuln_family,
                "engine": f.engine,
                "matched_engines": raw_meta.get("matched_engines") or [f.engine],
                "cve_id": raw_meta.get("cve_id"),
                "is_kev": bool(raw_meta.get("is_kev", False)),
                "epss_score": raw_meta.get("epss_score"),
                "priority_score": raw_meta.get("effective_priority_score"),
                "path": (f.file_path or "")[:200],
                "message": (f.message or "")[:400],
            }
        )

    system = (
        "You are a security engineer writing a VERITAS scan report. "
        "Return JSON only with shape: "
        '{"summary_markdown":"...","fixes":[{"i":0,"steps":["step1","step2"]}]} . '
        "summary_markdown MUST be GitHub-Flavored Markdown with real structure: "
        "start with '# VERITAS Scan Executive Summary', then '##' sections "
        "(Active Exploits & Threat Intelligence, Critical Issues, Themes, Prioritized Fixes, etc.), "
        "highlight any CISA KEV actively exploited CVEs, top EPSS probability scores, and cross-engine "
        "deduplication savings first, use '- ' bullet lists for findings and P1/P2 fixes (bold the priority label), "
        "and blank lines between sections. Keep steps concrete. No surrounding prose outside JSON."
    )
    user_msg = json.dumps(
        {
            "project": project_name,
            "target": target,
            "threat_intel_and_correlation": intel_summary or {},
            "findings": payload,
        },
        ensure_ascii=False,
    )

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(
                GROQ_URL,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": _model(),
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_msg},
                    ],
                },
            )
        if resp.status_code >= 400:
            logger.warning("groq report http %s: %s", resp.status_code, (resp.text or "")[:200])
            return {"status": "failed_http", "report_markdown": None, "countermeasures": {}, "code": resp.status_code}

        body = resp.json()
        content = (((body.get("choices") or [{}])[0].get("message") or {}).get("content")) or "{}"
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return {"status": "failed_parse", "report_markdown": None, "countermeasures": {}}

        report = str(parsed.get("summary_markdown") or "").strip()[:20000]
        fixes_raw = parsed.get("fixes") if isinstance(parsed.get("fixes"), list) else []
        countermeasures: dict[int, list[str]] = {}
        for row in fixes_raw:
            if not isinstance(row, dict):
                continue
            try:
                i = int(row.get("i"))
            except (TypeError, ValueError):
                continue
            steps = row.get("steps")
            if isinstance(steps, list) and steps:
                countermeasures[i] = [str(s)[:400] for s in steps[:8]]

        for i, steps in countermeasures.items():
            if 0 <= i < len(ranked):
                ranked[i].raw = {
                    **(ranked[i].raw or {}),
                    "ai_fix_steps": steps,
                }

        if not report:
            report = f"# VERITAS security summary\n\nReviewed {len(ranked)} finding(s) for **{project_name}**.\n"

        return {
            "status": "ok",
            "report_markdown": report,
            "countermeasures": countermeasures,
            "model": _model(),
            "findings_in_report": len(ranked),
        }
    except Exception as exc:
        logger.warning("groq report failed: %s", str(exc)[:200])
        return {
            "status": "failed_open",
            "report_markdown": None,
            "countermeasures": {},
            "error": str(exc)[:200],
        }
```

#### 5.2 `backend/app/services/scan_runner.py` (Phase 6A Pipeline Integration)
In `backend/app/services/scan_runner.py`[[5](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fscan_runner.py)]:
1. Add the imports at the top of `scan_runner.py`:
```python
from app.services.correlator import correlate_findings
from app.services.engines.trivy_sbom import run_trivy_sbom
from app.services.threat_intel import enrich_findings_with_intel
```
2. Add `"license"` to `_playbook_for`:
```python
def _playbook_for(family: str, severity: str) -> list[dict]:
    tips = {
        "sqli": ["Use parameterized queries / ORM bind parameters.", "Never concatenate user input into SQL."],
        "xss": ["Encode output for HTML context.", "Prefer framework auto-escaping; sanitize rich text carefully."],
        "csrf": ["Require anti-CSRF tokens on state-changing requests.", "Set SameSite=Lax/Strict on session cookies."],
        "secret": ["Rotate the exposed credential immediately.", "Remove secrets from git history; use a secret manager."],
        "sca": ["Upgrade the vulnerable dependency.", "Review advisories and apply patches or replacements."],
        "license": ["Replace the restricted copyleft dependency with a permissive alternative (MIT/Apache-2.0/BSD) or obtain legal review."],
        "other": ["Review the rule guidance and apply the least-privilege secure alternative."],
    }
    return [{"title": "Recommended countermeasure", "steps": tips.get(family, tips["other"]), "severity": severity}]
```
3. Inside `run_scan_job(scan_id: str)`, right after the engines & `review_repository` finish (just before `cleanup_workdir(workdir)` at line 506), run the SBOM generator, Correlator, and KEV/EPSS enrichment, and save the Phase 6A columns on each `Finding`[[5](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fscan_runner.py)]:

```python
                    # Phase 6A Step 1: Generate CycloneDX 1.5 SBOM & License Governance
                    sbom_res, sbom_meta = run_trivy_sbom(
                        session,
                        scan_id=scan.id,
                        project_id=project.id,
                        workdir=repo_path,
                    )
                    engine_meta.append(sbom_meta)
                    findings_out.extend(sbom_res.findings)

                    root = str(repo_path)
                    for nf in findings_out:
                        nf.file_path = public_repo_path(nf.file_path, repo_root=root)
                else:
                    for name in (*ALL_ENGINES, "openrouter_review"):
                        engine_meta.append({"engine": name, "skipped": "no repository workspace"})
                    _, sbom_meta = run_trivy_sbom(
                        session,
                        scan_id=scan.id,
                        project_id=project.id,
                        workdir=None,
                    )
                    engine_meta.append(sbom_meta)

                cleanup_workdir(workdir)
                workdir = None

                suppressed = {
                    row.fingerprint
                    for row in session.scalars(
                        select(FindingSuppression).where(FindingSuppression.project_id == project.id)
                    ).all()
                    if row.fingerprint
                }

                # Phase 6A Step 2: Cross-Engine Canonical Correlation & Deduplication
                corr_result = correlate_findings(findings_out, suppressed_fingerprints=suppressed)
                raw_findings_count = corr_result.raw_findings_count
                findings_out = corr_result.findings

                # Phase 6A Step 3: Offline CISA KEV + FIRST EPSS Enrichment & Priority Sorting
                findings_out = enrich_findings_with_intel(session, findings_out)
                kev_count = sum(1 for nf in findings_out if (nf.raw or {}).get("is_kev"))
                intel_summary = {
                    "headline": (
                        f"Correlated {raw_findings_count} raw tool hits into {len(findings_out)} unique findings; "
                        f"{kev_count} are in CISA KEV"
                    ),
                    "raw_findings_count": raw_findings_count,
                    "correlated_findings_count": len(findings_out),
                    "deduplicated_count": corr_result.deduplicated_count,
                    "kev_count": kev_count,
                }

                ai_status = "skipped"
                ai_report = None
                if scan.scan_mode == "rules_plus_ai" or want_review:
                    _check_cancel(session, scan)
                    _set_progress(
                        session,
                        scan,
                        phase="reporting",
                        percent=90,
                        log="Writing the security report…",
                    )
                    report_meta = generate_final_report(
                        findings_out,
                        project_name=project.name,
                        target=scan.target,
                        intel_summary=intel_summary,
                    )
                    ai_status = report_meta.get("status") or "ok"
                    ai_report = report_meta.get("report_markdown")
                    engine_meta.append(
                        {
                            "engine": "groq_report",
                            "status": ai_status,
                            "model": report_meta.get("model"),
                            "findings_in_report": report_meta.get("findings_in_report"),
                        }
                    )
                    _set_progress(
                        session,
                        scan,
                        phase="reporting",
                        percent=93,
                        log="Report draft ready",
                    )

                _check_cancel(session, scan)
                _set_progress(
                    session,
                    scan,
                    phase="reporting",
                    percent=95,
                    log=f"Saving {len(findings_out)} finding(s)…",
                )
                for old in session.scalars(select(Finding).where(Finding.scan_id == scan.id)):
                    session.delete(old)
                session.commit()

                severity_counts: Counter[str] = Counter()
                family_counts: Counter[str] = Counter()
                suppressed_count = 0
                for nf in findings_out:
                    raw_meta = nf.raw if isinstance(nf.raw, dict) else {}
                    fp = str(raw_meta.get("canonical_fingerprint") or nf.fingerprint())
                    is_supp = bool(raw_meta.get("is_suppressed")) or (fp in suppressed)
                    status = "false_positive" if is_supp else "open"
                    if status == "false_positive":
                        suppressed_count += 1
                    severity_counts[nf.severity] += 1
                    family_counts[nf.vuln_family] += 1
                    ai_verdict = raw_meta.get("ai_verdict")
                    ai_rationale = raw_meta.get("ai_rationale")
                    matched_engines = raw_meta.get("matched_engines") or [nf.engine]
                    engine_count = int(raw_meta.get("engine_count") or len(matched_engines))
                    confidence_level = str(raw_meta.get("confidence_level") or "medium")
                    cve_id = raw_meta.get("cve_id")
                    epss_score = raw_meta.get("epss_score")
                    epss_percentile = raw_meta.get("epss_percentile")
                    is_kev = bool(raw_meta.get("is_kev", False))
                    kev_due_date = raw_meta.get("kev_due_date")
                    priority_score = float(
                        raw_meta.get("effective_priority_score")
                        or nf.risk_score(criticality=project.criticality)
                    )
                    session.add(
                        Finding(
                            scan_id=scan.id,
                            engine=nf.engine,
                            rule_id=nf.rule_id,
                            vuln_family=nf.vuln_family,
                            cwe=nf.cwe,
                            owasp_category=nf.owasp_category,
                            severity=nf.severity,
                            title=nf.title[:512],
                            message=nf.message,
                            file_path=nf.file_path,
                            line_start=nf.line_start,
                            line_end=nf.line_end,
                            snippet=nf.snippet,
                            risk_score=nf.risk_score(criticality=project.criticality),
                            status=status,
                            fingerprint=fp,
                            ai_verdict=ai_verdict,
                            ai_rationale=ai_rationale,
                            countermeasures_json=json.dumps(
                                _countermeasures_for(nf, nf.vuln_family, nf.severity)
                            ),
                            raw_json=json.dumps(nf.raw)[:20000] if nf.raw else None,
                            cve_id=cve_id,
                            matched_engines_json=json.dumps(matched_engines),
                            engine_count=engine_count,
                            confidence_level=confidence_level,
                            epss_score=epss_score,
                            epss_percentile=epss_percentile,
                            is_kev=is_kev,
                            kev_due_date=kev_due_date,
                            effective_priority_score=priority_score,
                        )
                    )

                open_findings = [
                    nf
                    for nf in findings_out
                    if not (
                        bool((nf.raw or {}).get("is_suppressed"))
                        or str((nf.raw or {}).get("canonical_fingerprint") or nf.fingerprint()) in suppressed
                    )
                ]
```
And in `summary = { ... }` right below that in `scan_runner.py`, include the correlation counts:
```python
                summary = {
                    "findings_count": len(findings_out),
                    "raw_findings_count": raw_findings_count,
                    "correlated_findings_count": len(findings_out),
                    "deduplicated_count": corr_result.deduplicated_count,
                    "kev_count": kev_count,
                    "open_count": open_count,
                    "suppressed_count": suppressed_count,
                    "by_severity": dict(severity_counts),
                    "by_family": dict(family_counts),
                    "engines": engine_meta,
                    "scan_mode": scan.scan_mode,
                    "scan_scope": scan.scan_scope or "full",
                    "security_level": scan.security_level,
                    "options": options,
                    "ai_status": ai_status,
                    "ai_report": ai_report,
                    "max_risk": max_risk,
                    "commit_short": scan.commit_short,
                    "commit_sha": scan.commit_sha,
                    "workspace_purged": True,
                    "policy_failed": policy_failed,
                    "fail_severity": fail_at,
                }
```

#### 5.3 `backend/app/services/projects.py` (Serialize Phase 6A Fields, Filtering, & SBOM Service Functions)
Update `public_finding`, `list_findings`, `delete_project`, and add `get_scan_sbom` in `backend/app/services/projects.py`[[14](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fservices%2Fprojects.py)]:

```python
# At the top of backend/app/services/projects.py, update imports from app.models:
from sqlalchemy import case, desc, func, select
from app.models import Finding, FindingSuppression, Project, Scan, ScanSbomArtifact, User
from app.services.engines.trivy_sbom import analyze_cyclonedx_sbom
```

Update `public_finding(finding: Finding) -> dict` in `backend/app/services/projects.py`:
```python
def public_finding(finding: Finding) -> dict:
    countermeasures = None
    if finding.countermeasures_json:
        try:
            countermeasures = json.loads(finding.countermeasures_json)
        except json.JSONDecodeError:
            countermeasures = None

    matched_engines: list[str] = []
    raw_matched = getattr(finding, "matched_engines_json", None)
    if raw_matched:
        try:
            parsed = json.loads(raw_matched)
            if isinstance(parsed, list):
                matched_engines = [str(e) for e in parsed if e]
        except json.JSONDecodeError:
            matched_engines = []
    if not matched_engines and finding.engine:
        matched_engines = [finding.engine]

    engine_count = int(getattr(finding, "engine_count", 0) or len(matched_engines) or 1)
    priority_score = float(getattr(finding, "effective_priority_score", 0.0) or 0.0)
    if priority_score <= 0.0 and finding.risk_score:
        priority_score = float(finding.risk_score)

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "engine": finding.engine,
        "rule_id": finding.rule_id,
        "vuln_family": finding.vuln_family,
        "cwe": finding.cwe,
        "owasp_category": finding.owasp_category,
        "severity": finding.severity,
        "title": finding.title,
        "message": finding.message,
        "file_path": public_repo_path(finding.file_path),
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "snippet": finding.snippet,
        "risk_score": finding.risk_score,
        "status": finding.status,
        "fingerprint": finding.fingerprint,
        "ai_verdict": finding.ai_verdict,
        "ai_rationale": finding.ai_rationale,
        "countermeasures": countermeasures,
        # Phase 6A fields:
        "cve_id": getattr(finding, "cve_id", None),
        "matched_engines": matched_engines,
        "engine_count": engine_count,
        "confidence_level": getattr(finding, "confidence_level", None) or "medium",
        "epss_score": getattr(finding, "epss_score", None),
        "epss_percentile": getattr(finding, "epss_percentile", None),
        "is_kev": bool(getattr(finding, "is_kev", False)),
        "kev_due_date": getattr(finding, "kev_due_date", None),
        "effective_priority_score": priority_score,
        "created_at": finding.created_at,
    }
```

Update `delete_project` in `backend/app/services/projects.py` to also clean up `ScanSbomArtifact` rows:
```python
    for row in db.scalars(select(ScanSbomArtifact).where(ScanSbomArtifact.project_id == project.id)):
        db.delete(row)
```

Update `list_findings` and add `get_scan_sbom` in `backend/app/services/projects.py`:
```python
def list_findings(
    db: Session,
    user: User,
    scan_id: str,
    *,
    is_kev: bool | None = None,
    min_epss: float | None = None,
    min_engines: int | None = None,
    category: str | None = None,
    sort_by: str = "priority",
) -> list[Finding]:
    get_owned_scan(db, user, scan_id)
    query = select(Finding).where(Finding.scan_id == scan_id)

    if is_kev is not None:
        query = query.where(Finding.is_kev.is_(is_kev))
    if min_epss is not None:
        query = query.where(Finding.epss_score.isnot(None), Finding.epss_score >= float(min_epss))
    if min_engines is not None:
        query = query.where(Finding.engine_count >= int(min_engines))
    if category:
        cat = category.strip().lower()
        query = query.where(Finding.vuln_family == cat)

    sev_rank = case(
        (Finding.severity == "critical", 5),
        (Finding.severity == "high", 4),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 2),
        else_=1,
    )

    if sort_by == "severity":
        query = query.order_by(desc(sev_rank), desc(Finding.effective_priority_score), desc(Finding.risk_score))
    elif sort_by == "epss":
        query = query.order_by(
            desc(case((Finding.epss_score.is_(None), -1.0), else_=Finding.epss_score)),
            desc(Finding.effective_priority_score),
            desc(Finding.risk_score),
        )
    else:
        query = query.order_by(
            desc(Finding.effective_priority_score),
            desc(Finding.is_kev),
            desc(Finding.risk_score),
        )

    return list(db.scalars(query))


def get_scan_sbom(db: Session, user: User, project_id: str, scan_id: str) -> ScanSbomArtifact:
    project = get_owned_project(db, user, project_id)
    scan, scan_proj = get_owned_scan(db, user, scan_id)
    if scan_proj.id != project.id:
        raise HTTPException(status_code=404, detail="Scan not found in this project.")
    artifact = db.scalar(
        select(ScanSbomArtifact).where(
            ScanSbomArtifact.scan_id == scan.id,
            ScanSbomArtifact.project_id == project.id,
        )
    )
    if not artifact:
        raise HTTPException(status_code=404, detail="SBOM artifact not found for this scan.")
    return artifact


def public_scan_sbom(artifact: ScanSbomArtifact) -> dict:
    try:
        sbom_dict = json.loads(artifact.sbom_json or "{}")
    except json.JSONDecodeError:
        sbom_dict = {}
    analyzed = analyze_cyclonedx_sbom(sbom_dict)
    try:
        license_summary = json.loads(artifact.license_summary_json or "{}")
    except json.JSONDecodeError:
        license_summary = analyzed.license_summary

    return {
        "id": artifact.id,
        "scan_id": artifact.scan_id,
        "project_id": artifact.project_id,
        "spec_version": artifact.spec_version,
        "component_count": artifact.component_count,
        "policy_violations_count": artifact.policy_violations_count,
        "license_summary": license_summary,
        "components": analyzed.components,
        "created_at": artifact.created_at,
    }
```

#### 5.4 `backend/app/api/workspace.py` (Extended Findings Route + SBOM Routes)
In `backend/app/api/workspace.py`, update `scan_findings` and add the two new SBOM endpoints (`GET /workspace/projects/{project_id}/scans/{scan_id}/sbom` and `GET /workspace/projects/{project_id}/scans/{scan_id}/sbom/download`)[[3](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fapi%2Fworkspace.py)]:

```python
from fastapi.responses import RedirectResponse, Response
```

Replace `scan_findings` and add the SBOM routes in `backend/app/api/workspace.py`:
```python
@router.get("/projects/{project_id}/scans/{scan_id}/findings")
@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
    project_id: str | None = None,
    is_kev: bool | None = Query(default=None),
    min_epss: float | None = Query(default=None, ge=0.0, le=1.0),
    min_engines: int | None = Query(default=None, ge=1),
    category: str | None = Query(default=None),
    sort_by: str = Query(default="priority", pattern="^(priority|severity|epss)$"),
):
    if project_id is not None:
        project_svc.get_owned_project(db, user, project_id)
    items = project_svc.list_findings(
        db,
        user,
        scan_id,
        is_kev=is_kev,
        min_epss=min_epss,
        min_engines=min_engines,
        category=category,
        sort_by=sort_by,
    )
    serialized = [project_svc.public_finding(f) for f in items]
    return {"items": serialized, "findings": serialized, "total": len(serialized)}


@router.get("/projects/{project_id}/scans/{scan_id}/sbom")
def get_project_scan_sbom(
    project_id: str,
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    artifact = project_svc.get_scan_sbom(db, user, project_id, scan_id)
    return project_svc.public_scan_sbom(artifact)


@router.get("/projects/{project_id}/scans/{scan_id}/sbom/download")
def download_project_scan_sbom(
    project_id: str,
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    artifact = project_svc.get_scan_sbom(db, user, project_id, scan_id)
    filename = f"veritas-sbom-scan-{scan_id}.cdx.json"
    return Response(
        content=artifact.sbom_json,
        media_type="application/vnd.cyclonedx+json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
```

#### 5.5 `backend/app/api/admin.py` (Threat Intel Admin Endpoints)
Append these two routes to the bottom of `backend/app/api/admin.py`[[4](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Fbackend%2Fapp%2Fapi%2Fadmin.py)]:

```python
from app.services.threat_intel import get_threat_intel_status, sync_threat_intel_feeds


@router.get("/threat-intel/status")
def threat_intel_status(_: User = Depends(require_admin), db: Session = Depends(db_session)):
    """View CveIntelCache statistics (total cached CVEs, KEV count, last sync timestamp)."""
    return get_threat_intel_status(db)


@router.post("/threat-intel/sync")
def threat_intel_sync(
    include_bulk_epss: bool = False,
    _: User = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Trigger an immediate CISA KEV + FIRST EPSS threat intelligence sync."""
    return sync_threat_intel_feeds(db, include_bulk_epss=include_bulk_epss)
```

---

### 6. React 18 + TypeScript Frontend Updates

#### 6.1 `frontend/src/lib/workspace.ts`
Extend `Scan` (summary fields), `Finding` (Phase 6A fields), and add the `ScanSbom` types in `frontend/src/lib/workspace.ts`[[11](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Ffrontend%2Fsrc%2Flib%2Fworkspace.ts)]:

```typescript
// In `Scan["summary"]` inside frontend/src/lib/workspace.ts, add:
  summary?: {
    findings_count?: number;
    raw_findings_count?: number;
    correlated_findings_count?: number;
    deduplicated_count?: number;
    kev_count?: number;
    engine?: string;
    note?: string;
    by_severity?: Record<string, number>;
    by_family?: Record<string, number>;
    ai_status?: string;
    ai_report?: string | null;
    max_risk?: number;
    commit_short?: string;
    commit_sha?: string;
    engines?: Array<Record<string, unknown>>;
    options?: Record<string, unknown>;
    policy_failed?: boolean;
    fail_severity?: string;
  } | null;

// Replace `export type Finding = ...` with:
export type Finding = {
  id: string;
  scan_id: string;
  engine: string;
  rule_id?: string | null;
  vuln_family: string;
  cwe?: string | null;
  owasp_category?: string | null;
  severity: string;
  title: string;
  message?: string | null;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  snippet?: string | null;
  risk_score: number;
  status: string;
  fingerprint?: string | null;
  ai_verdict?: string | null;
  ai_rationale?: string | null;
  countermeasures?: Array<{ title?: string; steps?: string[] }> | null;
  // Phase 6A fields
  cve_id?: string | null;
  matched_engines?: string[];
  engine_count?: number;
  confidence_level?: "high" | "medium" | "low" | string;
  epss_score?: number | null;
  epss_percentile?: number | null;
  is_kev?: boolean;
  kev_due_date?: string | null;
  effective_priority_score?: number;
};

export type SbomComponent = {
  name: string;
  version: string;
  purl: string;
  ecosystem: string;
  licenses: string[];
  risk_tier: "permissive" | "weak_copyleft" | "restricted_copyleft" | "unknown" | string;
  source_file?: string;
};

export type ScanSbomResponse = {
  id: string;
  scan_id: string;
  project_id: string;
  spec_version: string;
  component_count: number;
  policy_violations_count: number;
  license_summary: {
    permissive?: number;
    weak_copyleft?: number;
    restricted_copyleft?: number;
    unknown?: number;
    by_license?: Record<string, number>;
  };
  components: SbomComponent[];
  created_at?: string | null;
};
```

#### 6.2 `frontend/src/components/ScanReportModal.tsx`
Replace `frontend/src/components/ScanReportModal.tsx` with this upgraded version[[13](https://www.google.com/url?sa=E&q=https%3A%2F%2Fraw.githubusercontent.com%2Fbharani-01%2FVERITAS%2Fmain%2Ffrontend%2Fsrc%2Fcomponents%2FScanReportModal.tsx)]. It preserves 100% of your existing modal/page layout, export dropdown, share sheet, live scan logs, and finding drawer while adding:
- **Deduplication Callout Banner** when `raw_findings_count > correlated_findings_count`
- **"Findings" vs. "SBOM & Licenses" Tab Switcher**
- **Quick-Filter Chips**: `All`, `Actively Exploited (KEV)`, `High EPSS (>10%)`, `Multi-Engine Confirmed (2+)`, and `License Risks`
- **CISA KEV crimson badge (`ACTIVE EXPLOIT · KEV`)**, **EPSS Pill** (amber $\ge 10\%$, red $\ge 30\%$), and **Multi-Engine Confirmation Pill** (`Confirmed by N engines` with hover tooltip) in both the findings table and the finding detail drawer
- **SBOM & License Inventory Tab** with the 4 summary cards, search input, component table, and **`Download CycloneDX (.cdx.json)`** button

```tsx
import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { LoadingMark } from "./LoadingMark";
import { MarkdownReport } from "./MarkdownReport";
import { OrbitLoader } from "./OrbitLoader";
import { api } from "../lib/api";
import { githubBlobUrl, githubCommitUrl } from "../lib/githubLinks";
import { exportScanReport, sortFindingsByRisk, type ExportFormat } from "../lib/reportExport";
import { formatScanDuration, scanTriggerLabel, shortCommit } from "../lib/scanDisplay";
import { scanProgressLabel } from "../lib/scanProgress";
import type { Finding, Scan, ScanSbomResponse } from "../lib/workspace";

type Props = {
  scan: Scan;
  findings: Finding[];
  findingsLoading?: boolean;
  projectName?: string;
  githubRepoFullName?: string | null;
  onClose: () => void;
  onShared?: (scan: Scan) => void;
  onFindingsChange?: (items: Finding[]) => void;
  variant?: "modal" | "page";
  onCancelScan?: () => void;
  cancelBusy?: boolean;
};

type QuickFilter = "all" | "kev" | "high_epss" | "multi_engine" | "license";
type ReportTab = "findings" | "sbom";

const EXPORT_OPTIONS: { value: ExportFormat; label: string }[] = [
  { value: "md", label: "Markdown (.md)" },
  { value: "json", label: "JSON (.json)" },
  { value: "csv", label: "CSV (.csv)" },
  { value: "html", label: "HTML (.html)" },
  { value: "sarif", label: "SARIF (.sarif)" },
];

function IconExport() {
  return (
    <svg className="report-action-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M12 3v10m0 0l3.5-3.5M12 13L8.5 9.5M5 15v3a2 2 0 002 2h10a2 2 0 002-2v-3"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function IconBack() {
  return (
    <svg className="finding-back-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M15 6l-6 6 6 6"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function IconShare() {
  return (
    <svg className="report-action-icon" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="18" cy="5" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <circle cx="6" cy="12" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <circle cx="18" cy="19" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <path d="M8.4 10.8l7.2-4.6M8.4 13.2l7.2 4.6" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
    </svg>
  );
}

function shareCaption(scan: Scan, projectName?: string) {
  const name = projectName || scan.project_name || scan.target;
  const version = shortCommit(scan.commit_short, scan.commit_sha);
  return version ? `${name} · ${version}` : name;
}

function CommitLink({
  short,
  sha,
  repo,
}: {
  short: string;
  sha?: string | null;
  repo?: string | null;
}) {
  const display = shortCommit(short, sha) || short.slice(0, 7);
  const href = githubCommitUrl(repo, sha || short);
  if (!href) return <code title={sha || undefined}>{display}</code>;
  return (
    <a className="scan-git-link" href={href} target="_blank" rel="noreferrer" title={`Open ${display} on GitHub`}>
      <code>{display}</code>
    </a>
  );
}

function FindingThreatBadges({ finding }: { finding: Finding }) {
  const epssPct =
    finding.epss_score !== null && finding.epss_score !== undefined
      ? finding.epss_score * 100
      : null;
  const engineCount = finding.engine_count ?? finding.matched_engines?.length ?? 1;
  const matchedList = finding.matched_engines?.length ? finding.matched_engines : [finding.engine];

  return (
    <span style={{ display: "inline-flex", alignItems: "center", flexWrap: "wrap", gap: "6px", marginLeft: "6px" }}>
      {finding.is_kev ? (
        <span
          title={finding.kev_due_date ? `CISA KEV Due Date: ${finding.kev_due_date}` : "Actively exploited in the wild (CISA KEV)"}
          style={{
            padding: "2px 7px",
            borderRadius: "5px",
            backgroundColor: "rgba(185, 28, 28, 0.32)",
            border: "1px solid #ef4444",
            color: "#fecaca",
            fontSize: "0.68rem",
            fontWeight: 800,
            letterSpacing: "0.04em",
          }}
        >
          ACTIVE EXPLOIT · KEV
        </span>
      ) : null}

      {finding.cve_id ? (
        <span
          style={{
            padding: "1px 6px",
            borderRadius: "5px",
            backgroundColor: "rgba(59, 130, 246, 0.14)",
            border: "1px solid rgba(59, 130, 246, 0.35)",
            color: "#93c5fd",
            fontSize: "0.7rem",
            fontFamily: "monospace",
          }}
        >
          {finding.cve_id}
        </span>
      ) : null}

      {epssPct !== null ? (
        <span
          title={
            finding.epss_percentile != null
              ? `FIRST EPSS 30-day exploit probability (${(finding.epss_percentile * 100).toFixed(1)}th percentile)`
              : "FIRST EPSS 30-day exploit probability"
          }
          style={{
            padding: "1px 6px",
            borderRadius: "5px",
            fontSize: "0.7rem",
            fontWeight: 600,
            backgroundColor:
              epssPct >= 30
                ? "rgba(220, 38, 38, 0.2)"
                : epssPct >= 10
                  ? "rgba(245, 158, 11, 0.2)"
                  : "rgba(30, 41, 59, 0.75)",
            border:
              epssPct >= 30
                ? "1px solid rgba(248, 113, 113, 0.55)"
                : epssPct >= 10
                  ? "1px solid rgba(251, 191, 36, 0.55)"
                  : "1px solid var(--border-subtle, #1e293b)",
            color: epssPct >= 30 ? "#fca5a5" : epssPct >= 10 ? "#fcd34d" : "#94a3b8",
          }}
        >
          EPSS: {epssPct.toFixed(1)}%
        </span>
      ) : null}

      {engineCount > 1 ? (
        <span
          title={`Confirmed by: ${matchedList.join(", ")}`}
          style={{
            padding: "1px 7px",
            borderRadius: "5px",
            backgroundColor: "rgba(16, 185, 129, 0.16)",
            border: "1px solid rgba(52, 211, 153, 0.45)",
            color: "#6ee7b7",
            fontSize: "0.7rem",
            fontWeight: 600,
          }}
        >
          Confirmed by {engineCount} engines
        </span>
      ) : null}
    </span>
  );
}

export function ScanReportModal({
  scan,
  findings,
  findingsLoading = false,
  projectName,
  githubRepoFullName,
  onClose,
  onShared,
  onFindingsChange: _onFindingsChange,
  variant = "modal",
  onCancelScan,
  cancelBusy = false,
}: Props) {
  const [shareUrl, setShareUrl] = useState<string | null>(
    scan.share_token ? `${window.location.origin}/report/${scan.share_token}` : null,
  );
  const [shareOpen, setShareOpen] = useState(false);
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [exportPos, setExportPos] = useState<{ top: number; left: number } | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);

  // Phase 6A state: Tabs, Quick-Filters, and SBOM Inventory
  const [activeTab, setActiveTab] = useState<ReportTab>("findings");
  const [quickFilter, setQuickFilter] = useState<QuickFilter>("all");
  const [sbom, setSbom] = useState<ScanSbomResponse | null>(null);
  const [sbomLoading, setSbomLoading] = useState(false);
  const [sbomError, setSbomError] = useState<string | null>(null);
  const [sbomSearch, setSbomSearch] = useState("");

  const exportWrapRef = useRef<HTMLDivElement>(null);
  const exportBtnRef = useRef<HTMLButtonElement>(null);
  const exportMenuRef = useRef<HTMLDivElement>(null);
  const liveLogRef = useRef<HTMLDivElement>(null);

  const sorted = useMemo(() => {
    return [...findings].sort((a, b) => {
      const pa = a.effective_priority_score ?? a.risk_score ?? 0;
      const pb = b.effective_priority_score ?? b.risk_score ?? 0;
      if (pb !== pa) return pb - pa;
      return (b.risk_score || 0) - (a.risk_score || 0);
    });
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return sorted.filter((f) => {
      if (quickFilter === "kev") return !!f.is_kev;
      if (quickFilter === "high_epss") return (f.epss_score ?? 0) >= 0.1;
      if (quickFilter === "multi_engine") return (f.engine_count ?? f.matched_engines?.length ?? 1) >= 2;
      if (quickFilter === "license") return f.vuln_family === "license" || f.engine === "trivy_license";
      return true;
    });
  }, [sorted, quickFilter]);

  const caption = shareCaption(scan, projectName);
  const scanning = scan.status === "queued" || scan.status === "running";
  const progressPct = Math.max(0, Math.min(100, Number(scan.progress?.percent ?? (scanning ? 2 : 100))));
  const progressLabel = scanProgressLabel(scan.progress, scan.status);
  const liveLogs = scan.progress?.logs || [];
  const findingsSoFar = scan.progress?.findings_so_far ?? 0;

  const aiReport = scan.summary?.ai_report?.trim() || null;
  const rawFindingsCount = scan.summary?.raw_findings_count ?? sorted.length;
  const correlatedFindingsCount = scan.summary?.correlated_findings_count ?? sorted.length;

  useEffect(() => {
    if (activeTab !== "sbom" || scanning || !scan.project_id || !scan.id) return;
    let cancelled = false;
    setSbomLoading(true);
    setSbomError(null);
    api<ScanSbomResponse>(`/workspace/projects/${scan.project_id}/scans/${scan.id}/sbom`)
      .then((res) => {
        if (!cancelled) setSbom(res);
      })
      .catch((err: Error) => {
        if (!cancelled) setSbomError(err.message);
      })
      .finally(() => {
        if (!cancelled) setSbomLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeTab, scanning, scan.project_id, scan.id]);

  const filteredSbomComponents = useMemo(() => {
    if (!sbom?.components) return [];
    const q = sbomSearch.trim().toLowerCase();
    if (!q) return sbom.components;
    return sbom.components.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.version.toLowerCase().includes(q) ||
        c.purl.toLowerCase().includes(q) ||
        c.licenses.some((l) => l.toLowerCase().includes(q)),
    );
  }, [sbom, sbomSearch]);

  useEffect(() => {
    const el = liveLogRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [liveLogs.length, scanning]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      if (selected) {
        setSelected(null);
        return;
      }
      if (shareOpen) {
        setShareOpen(false);
        return;
      }
      if (exportOpen) {
        setExportOpen(false);
        return;
      }
      if (variant === "page") return;
      onClose();
    }
    function onDoc(e: MouseEvent) {
      const t = e.target as Node;
      if (exportWrapRef.current?.contains(t) || exportMenuRef.current?.contains(t)) return;
      setExportOpen(false);
    }
    function placeMenu() {
      const btn = exportBtnRef.current;
      if (!btn || !exportOpen) return;
      const r = btn.getBoundingClientRect();
      const width = 208;
      const left = Math.min(Math.max(8, r.right - width), window.innerWidth - width - 8);
      setExportPos({ top: r.bottom + 6, left });
    }
    window.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDoc);
    window.addEventListener("resize", placeMenu);
    window.addEventListener("scroll", placeMenu, true);
    placeMenu();
    return () => {
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDoc);
      window.removeEventListener("resize", placeMenu);
      window.removeEventListener("scroll", placeMenu, true);
    };
  }, [shareOpen, exportOpen, onClose, selected, variant]);

  function toggleExport() {
    setExportOpen((open) => {
      if (open) return false;
      const btn = exportBtnRef.current;
      if (btn) {
        const r = btn.getBoundingClientRect();
        const width = 208;
        const left = Math.min(Math.max(8, r.right - width), window.innerWidth - width - 8);
        setExportPos({ top: r.bottom + 6, left });
      }
      return true;