from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    inspect,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, mapped_column, relationship

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
    # Phase 6B: SLA & Suppression Governance Policy
    sla_critical_days: Mapped[int] = mapped_column(Integer, default=7)
    sla_high_days: Mapped[int] = mapped_column(Integer, default=14)
    sla_medium_days: Mapped[int] = mapped_column(Integer, default=30)
    sla_low_days: Mapped[int] = mapped_column(Integer, default=90)
    require_suppression_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ProjectMember(Base):
    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_member_user"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(32), default="developer", index=True)
    added_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


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
    raw_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlated_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    kev_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_in_app: Mapped[bool] = mapped_column(Boolean, default=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    options_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class FindingPhase6AMixin:
    """Columns added to the `Finding` model (`findings` table) in Phase 6A."""

    cve_id = Column(String(64), nullable=True, index=True)
    matched_engines_json = Column(Text, nullable=False, default='["unknown"]')
    engine_count = Column(Integer, nullable=False, default=1)
    confidence_level = Column(String(32), nullable=False, default="medium")
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    is_kev = Column(Boolean, nullable=False, default=False, index=True)
    kev_due_date = Column(String(32), nullable=True)
    effective_priority_score = Column(Float, nullable=False, default=0.0, index=True)
    # Phase 6B: SLA Tracking columns
    sla_due_at = Column(DateTime(timezone=True), nullable=True)
    sla_breached = Column(Boolean, nullable=False, default=False)


class Finding(FindingPhase6AMixin, Base):
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def __init__(self, **kwargs):
        if "category" in kwargs and "vuln_family" not in kwargs:
            kwargs["vuln_family"] = kwargs.pop("category")
        if "description" in kwargs and "message" not in kwargs:
            kwargs["message"] = kwargs.pop("description")
        if "line_number" in kwargs and "line_start" not in kwargs:
            kwargs["line_start"] = kwargs.pop("line_number")
        if "code_snippet" in kwargs and "snippet" not in kwargs:
            kwargs["snippet"] = kwargs.pop("code_snippet")
        if "countermeasure" in kwargs and "countermeasures_json" not in kwargs:
            cm = kwargs.pop("countermeasure")
            kwargs["countermeasures_json"] = (
                json.dumps([{"title": "Remediation", "steps": [cm]}]) if cm else None
            )
        if "owasp" in kwargs and "owasp_category" not in kwargs:
            kwargs["owasp_category"] = kwargs.pop("owasp")
        kwargs.pop("project_id", None)
        kwargs.pop("is_suppressed", None)
        super().__init__(**kwargs)

    @property
    def category(self) -> str:
        return self.vuln_family or "sast"

    @property
    def description(self) -> str:
        return self.message or ""

    @property
    def line_number(self) -> int:
        return self.line_start or 0

    @property
    def code_snippet(self) -> str | None:
        return self.snippet

    @property
    def countermeasure(self) -> str | None:
        return self.countermeasures_json

    @property
    def owasp(self) -> str | None:
        return self.owasp_category

    @property
    def is_suppressed(self) -> bool:
        return self.status == "false_positive"


class FindingSuppression(Base):
    __tablename__ = "finding_suppressions"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint", name="uq_project_fingerprint"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    # Phase 6B: Two-Person Governance & Expiration
    status: Mapped[str] = mapped_column(String(32), default="approved", index=True)
    suppression_type: Mapped[str] = mapped_column(String(32), default="false_positive")
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    reviewed_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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


class CveIntelCache(Base):
    __tablename__ = "cve_intel_cache"

    cve_id = Column(String(64), primary_key=True, index=True)
    is_kev = Column(Boolean, nullable=False, default=False, index=True)
    kev_vendor = Column(String(255), nullable=True)
    kev_product = Column(String(255), nullable=True)
    kev_date_added = Column(String(32), nullable=True)
    kev_due_date = Column(String(32), nullable=True)
    kev_ransomware_use = Column(String(64), nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class ScanSbomArtifact(Base):
    __tablename__ = "scan_sbom_artifacts"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_scan_sbom_artifacts_scan_id"),
        Index("ix_scan_sbom_artifacts_project_scan", "project_id", "scan_id"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    spec_version = Column(String(32), nullable=False, default="CycloneDX-1.5")
    component_count = Column(Integer, nullable=False, default=0)
    license_summary_json = Column(Text, nullable=False, default="{}")
    policy_violations_count = Column(Integer, nullable=False, default=0)
    sbom_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


def apply_phase6a_schema_migrations(engine: Engine) -> None:
    """
    Idempotent schema migration helper invoked on FastAPI startup after
    `Base.metadata.create_all(bind=engine)`. Safely adds Phase 6A columns
    to existing `findings` and `scans` tables without dropping any data.
    """
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    findings_migrations: list[tuple[str, str]] = [
        ("cve_id", "VARCHAR(64)"),
        ("matched_engines_json", "TEXT DEFAULT '[]' NOT NULL"),
        ("engine_count", "INTEGER DEFAULT 1 NOT NULL"),
        ("confidence_level", "VARCHAR(32) DEFAULT 'medium' NOT NULL"),
        ("epss_score", "FLOAT"),
        ("epss_percentile", "FLOAT"),
        ("is_kev", "BOOLEAN DEFAULT FALSE NOT NULL"),
        ("kev_due_date", "VARCHAR(32)"),
        ("effective_priority_score", "FLOAT DEFAULT 0.0 NOT NULL"),
    ]

    scans_migrations: list[tuple[str, str]] = [
        ("raw_findings_count", "INTEGER DEFAULT 0 NOT NULL"),
        ("correlated_findings_count", "INTEGER DEFAULT 0 NOT NULL"),
        ("kev_findings_count", "INTEGER DEFAULT 0 NOT NULL"),
    ]

    with engine.begin() as conn:
        if "findings" in existing_tables:
            existing_finding_cols = {col["name"] for col in inspector.get_columns("findings")}
            for col_name, col_ddl in findings_migrations:
                if col_name not in existing_finding_cols:
                    conn.execute(text(f"ALTER TABLE findings ADD COLUMN {col_name} {col_ddl}"))

            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_findings_cve_id ON findings (cve_id)")
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_findings_effective_priority_score "
                    "ON findings (effective_priority_score)"
                )
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_findings_is_kev ON findings (is_kev)")
            )

        if "scans" in existing_tables:
            existing_scan_cols = {col["name"] for col in inspector.get_columns("scans")}
            for col_name, col_ddl in scans_migrations:
                if col_name not in existing_scan_cols:
                    conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col_name} {col_ddl}"))
