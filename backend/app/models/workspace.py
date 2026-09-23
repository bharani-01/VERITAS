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
