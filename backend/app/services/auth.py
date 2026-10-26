from __future__ import annotations

import os
import secrets
from datetime import timedelta

from fastapi import Request
from sqlalchemy import func, inspect, select, text
from sqlalchemy.orm import Session

from app.core import database as db
from app.core.config import APP_ENV, BOOTSTRAP, SESSION_TTL_HOURS
from app.core.security import normalize_email, password_hasher, token_hash
from app.core.time import utcnow
from app.models import AuthSession, User
from app.services.audit import audit, snapshot
from app.services.profile import allocate_username


def apply_phase6c_schema_migrations() -> None:
    """Idempotent Phase 6C schema migration ensuring `blocked_ips` table and indexes exist."""
    from app.models.base import Base

    Base.metadata.create_all(bind=db.engine)
    with db.engine.begin() as connection:
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_blocked_ips_expires_at ON blocked_ips (expires_at)")
        )
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_blocked_ips_attack_category ON blocked_ips (attack_category)")
        )


def ensure_schema() -> None:
    """Add columns to existing SQLite databases created before this phase."""
    from app.models.base import Base
    from app.models.workspace import apply_phase6a_schema_migrations

    Base.metadata.create_all(bind=db.engine)
    apply_phase6a_schema_migrations(db.engine)
    apply_phase6c_schema_migrations()
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    if "users" in tables:
        columns = {column["name"] for column in inspector.get_columns("users")}
        with db.engine.begin() as connection:
            if "username" not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN username VARCHAR(32)"))
            if "avatar" not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN avatar VARCHAR(32) DEFAULT 'slate'"))
            connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username)"))
        with db.SessionLocal() as session:
            for user in session.scalars(select(User)).all():
                changed = False
                if not user.username:
                    seed = user.email.split("@")[0] if user.email else user.display_name
                    user.username = allocate_username(session, seed, exclude_user_id=user.id)
                    changed = True
                if not user.avatar:
                    user.avatar = "slate"
                    changed = True
                if changed:
                    session.add(user)
            session.commit()
    if "audit_events" in tables:
        audit_cols = {column["name"] for column in inspector.get_columns("audit_events")}
        if "context_json" not in audit_cols:
            with db.engine.begin() as connection:
                connection.execute(text("ALTER TABLE audit_events ADD COLUMN context_json TEXT"))

    if "projects" in tables:
        project_cols = {column["name"] for column in inspector.get_columns("projects")}
        project_alters = {
            "security_level": "ALTER TABLE projects ADD COLUMN security_level VARCHAR(16) DEFAULT 'standard'",
            "base_url": "ALTER TABLE projects ADD COLUMN base_url VARCHAR(512)",
            "criticality": "ALTER TABLE projects ADD COLUMN criticality VARCHAR(16) DEFAULT 'medium'",
            "scan_options_json": "ALTER TABLE projects ADD COLUMN scan_options_json TEXT",
            "notify_email_default": "ALTER TABLE projects ADD COLUMN notify_email_default BOOLEAN DEFAULT 1",
            "notify_in_app_default": "ALTER TABLE projects ADD COLUMN notify_in_app_default BOOLEAN DEFAULT 1",
            "auto_scan_on_push": "ALTER TABLE projects ADD COLUMN auto_scan_on_push BOOLEAN DEFAULT 0",
            "auto_scan_branch": "ALTER TABLE projects ADD COLUMN auto_scan_branch VARCHAR(128)",
            "github_webhook_id": "ALTER TABLE projects ADD COLUMN github_webhook_id INTEGER",
            "github_webhook_secret": "ALTER TABLE projects ADD COLUMN github_webhook_secret TEXT",
        }
        with db.engine.begin() as connection:
            for name, sql in project_alters.items():
                if name not in project_cols:
                    connection.execute(text(sql))

    if "scans" in tables:
        scan_cols = {column["name"] for column in inspector.get_columns("scans")}
        scan_alters = {
            "security_level": "ALTER TABLE scans ADD COLUMN security_level VARCHAR(16) DEFAULT 'standard'",
            "scan_mode": "ALTER TABLE scans ADD COLUMN scan_mode VARCHAR(32) DEFAULT 'rules_only'",
            "scan_scope": "ALTER TABLE scans ADD COLUMN scan_scope VARCHAR(16) DEFAULT 'full'",
            "ref": "ALTER TABLE scans ADD COLUMN ref VARCHAR(128)",
            "commit_sha": "ALTER TABLE scans ADD COLUMN commit_sha VARCHAR(64)",
            "commit_short": "ALTER TABLE scans ADD COLUMN commit_short VARCHAR(16)",
            "commit_message": "ALTER TABLE scans ADD COLUMN commit_message VARCHAR(512)",
            "commit_author": "ALTER TABLE scans ADD COLUMN commit_author VARCHAR(256)",
            "git_history_json": "ALTER TABLE scans ADD COLUMN git_history_json TEXT",
            "share_token": "ALTER TABLE scans ADD COLUMN share_token VARCHAR(64)",
            "progress_json": "ALTER TABLE scans ADD COLUMN progress_json TEXT",
            "eta_seconds": "ALTER TABLE scans ADD COLUMN eta_seconds INTEGER",
            "error_message": "ALTER TABLE scans ADD COLUMN error_message TEXT",
            "risk_summary_json": "ALTER TABLE scans ADD COLUMN risk_summary_json TEXT",
            "notify_email": "ALTER TABLE scans ADD COLUMN notify_email BOOLEAN DEFAULT 1",
            "notify_in_app": "ALTER TABLE scans ADD COLUMN notify_in_app BOOLEAN DEFAULT 1",
            "cancel_requested": "ALTER TABLE scans ADD COLUMN cancel_requested BOOLEAN DEFAULT 0",
            "options_json": "ALTER TABLE scans ADD COLUMN options_json TEXT",
            "raw_findings_count": "ALTER TABLE scans ADD COLUMN raw_findings_count INTEGER DEFAULT 0",
            "correlated_findings_count": "ALTER TABLE scans ADD COLUMN correlated_findings_count INTEGER DEFAULT 0",
            "kev_findings_count": "ALTER TABLE scans ADD COLUMN kev_findings_count INTEGER DEFAULT 0",
        }
        with db.engine.begin() as connection:
            for name, sql in scan_alters.items():
                if name not in scan_cols:
                    connection.execute(text(sql))
            connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_scans_share_token ON scans (share_token)"))

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

    if "github_connections" in tables:
        gh_cols = {column["name"] for column in inspector.get_columns("github_connections")}
        with db.engine.begin() as connection:
            if "needs_reauth" not in gh_cols:
                connection.execute(text("ALTER TABLE github_connections ADD COLUMN needs_reauth BOOLEAN DEFAULT 0"))

    apply_phase6b_schema_migrations()


def apply_phase6b_schema_migrations() -> None:
    """Idempotent Phase 6B schema migrations for SQLite and PostgreSQL."""
    from app.models.base import Base

    Base.metadata.create_all(bind=db.engine)
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())

    with db.engine.begin() as connection:
        if "projects" in tables:
            proj_cols = {c["name"] for c in inspector.get_columns("projects")}
            proj_alters = {
                "sla_critical_days": "ALTER TABLE projects ADD COLUMN sla_critical_days INTEGER DEFAULT 7",
                "sla_high_days": "ALTER TABLE projects ADD COLUMN sla_high_days INTEGER DEFAULT 14",
                "sla_medium_days": "ALTER TABLE projects ADD COLUMN sla_medium_days INTEGER DEFAULT 30",
                "sla_low_days": "ALTER TABLE projects ADD COLUMN sla_low_days INTEGER DEFAULT 90",
                "require_suppression_approval": "ALTER TABLE projects ADD COLUMN require_suppression_approval BOOLEAN DEFAULT 0",
            }
            for col_name, ddl in proj_alters.items():
                if col_name not in proj_cols:
                    connection.execute(text(ddl))

        if "findings" in tables:
            finding_cols = {c["name"] for c in inspector.get_columns("findings")}
            finding_alters = {
                "sla_due_at": "ALTER TABLE findings ADD COLUMN sla_due_at TIMESTAMP",
                "sla_breached": "ALTER TABLE findings ADD COLUMN sla_breached BOOLEAN DEFAULT 0",
            }
            for col_name, ddl in finding_alters.items():
                if col_name not in finding_cols:
                    connection.execute(text(ddl))

        if "finding_suppressions" in tables:
            supp_cols = {c["name"] for c in inspector.get_columns("finding_suppressions")}
            supp_alters = {
                "status": "ALTER TABLE finding_suppressions ADD COLUMN status VARCHAR(32) DEFAULT 'approved'",
                "suppression_type": "ALTER TABLE finding_suppressions ADD COLUMN suppression_type VARCHAR(32) DEFAULT 'false_positive'",
                "justification": "ALTER TABLE finding_suppressions ADD COLUMN justification TEXT",
                "requested_by_user_id": "ALTER TABLE finding_suppressions ADD COLUMN requested_by_user_id VARCHAR(36)",
                "reviewed_by_user_id": "ALTER TABLE finding_suppressions ADD COLUMN reviewed_by_user_id VARCHAR(36)",
                "reviewed_at": "ALTER TABLE finding_suppressions ADD COLUMN reviewed_at TIMESTAMP",
                "expires_at": "ALTER TABLE finding_suppressions ADD COLUMN expires_at TIMESTAMP",
            }
            for col_name, ddl in supp_alters.items():
                if col_name not in supp_cols:
                    connection.execute(text(ddl))
            connection.execute(
                text("CREATE INDEX IF NOT EXISTS ix_finding_suppressions_status ON finding_suppressions (status)")
            )


def active_admin_count(session: Session) -> int:

    return (
        session.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.status == "active"))
        or 0
    )


def create_session(session: Session, user: User, request: Request) -> str:
    raw = secrets.token_urlsafe(48)
    session.add(
        AuthSession(
            user_id=user.id,
            token_hash=token_hash(raw),
            expires_at=utcnow() + timedelta(hours=SESSION_TTL_HOURS),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    )
    return raw


def bootstrap_admin(session: Session | None = None) -> None:
    def _bootstrap_one(sess: Session, email: str, password: str, name: str) -> None:
        if not (email and password):
            return
        if sess.scalar(select(User).where(User.email == normalize_email(email))):
            return
        if len(password) < 12:
            raise RuntimeError("VERITAS bootstrap administrator password must be at least 12 characters.")
        admin = User(
            display_name=name.strip(),
            username=allocate_username(sess, email.split("@")[0] or "admin"),
            avatar="forest",
            email=normalize_email(email),
            password_hash=password_hasher.hash(password),
            role="admin",
            status="active",
            email_verified_at=utcnow(),
            approved_at=utcnow(),
            force_password_reset=True,
        )
        sess.add(admin)
        sess.flush()
        audit(sess, None, "bootstrap_admin_created", target=admin, after=snapshot(admin))
        sess.commit()

    def _run(sess: Session) -> None:
        v_email = os.getenv("VERITAS_BOOTSTRAP_ADMIN_EMAIL") or BOOTSTRAP.get("email") or ""
        v_pass = os.getenv("VERITAS_BOOTSTRAP_ADMIN_PASSWORD") or BOOTSTRAP.get("password") or ""
        v_name = os.getenv("VERITAS_BOOTSTRAP_ADMIN_NAME") or BOOTSTRAP.get("name") or "Administrator"
        _bootstrap_one(sess, v_email, v_pass, v_name)

        b_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL") or ""
        b_pass = os.getenv("BOOTSTRAP_ADMIN_PASSWORD") or ""
        b_name = os.getenv("BOOTSTRAP_ADMIN_NAME") or "Administrator"
        if b_email and b_email != v_email:
            _bootstrap_one(sess, b_email, b_pass, b_name)

    if session is not None:
        _run(session)
    else:
        with db.SessionLocal() as s:
            _run(s)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def bootstrap_admin_account(session: Session | None = None) -> None:
    bootstrap_admin(session)
