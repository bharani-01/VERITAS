from __future__ import annotations

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


def ensure_schema() -> None:
    """Add columns to existing SQLite databases created before this phase."""
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
        with db.engine.begin() as connection:
            alters = [
                ("security_level", "VARCHAR(16) DEFAULT 'standard'"),
                ("base_url", "VARCHAR(512)"),
                ("criticality", "VARCHAR(16) DEFAULT 'medium'"),
                ("scan_options_json", "TEXT"),
                ("notify_email_default", "BOOLEAN DEFAULT 1"),
                ("notify_in_app_default", "BOOLEAN DEFAULT 1"),
            ]
            for name, decl in alters:
                if name not in project_cols:
                    connection.execute(text(f"ALTER TABLE projects ADD COLUMN {name} {decl}"))

    if "scans" in tables:
        scan_cols = {column["name"] for column in inspector.get_columns("scans")}
        with db.engine.begin() as connection:
            alters = [
                ("security_level", "VARCHAR(16) DEFAULT 'standard'"),
                ("scan_mode", "VARCHAR(32) DEFAULT 'rules_only'"),
                ("ref", "VARCHAR(128)"),
                ("commit_sha", "VARCHAR(64)"),
                ("commit_short", "VARCHAR(16)"),
                ("commit_message", "VARCHAR(512)"),
                ("commit_author", "VARCHAR(256)"),
                ("git_history_json", "TEXT"),
                ("share_token", "VARCHAR(64)"),
                ("progress_json", "TEXT"),
                ("eta_seconds", "INTEGER"),
                ("error_message", "TEXT"),
                ("risk_summary_json", "TEXT"),
                ("notify_email", "BOOLEAN DEFAULT 1"),
                ("notify_in_app", "BOOLEAN DEFAULT 1"),
            ]
            for name, decl in alters:
                if name not in scan_cols:
                    connection.execute(text(f"ALTER TABLE scans ADD COLUMN {name} {decl}"))
            connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_scans_share_token ON scans (share_token)"))


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


def bootstrap_admin() -> None:
    with db.SessionLocal() as session:
        if session.scalar(select(func.count()).select_from(User)):
            return
        if APP_ENV == "production" and not all(BOOTSTRAP.values()):
            raise RuntimeError("VERITAS bootstrap administrator variables are required for an empty production database.")
        if not all(BOOTSTRAP.values()):
            return
        if len(BOOTSTRAP["password"]) < 12:
            raise RuntimeError("VERITAS bootstrap administrator password must be at least 12 characters.")
        admin = User(
            display_name=BOOTSTRAP["name"].strip(),
            username=allocate_username(session, BOOTSTRAP["email"].split("@")[0] or "admin"),
            avatar="forest",
            email=normalize_email(BOOTSTRAP["email"]),
            password_hash=password_hasher.hash(BOOTSTRAP["password"]),
            role="admin",
            status="active",
            email_verified_at=utcnow(),
            approved_at=utcnow(),
            force_password_reset=True,
        )
        session.add(admin)
        session.flush()
        audit(session, None, "bootstrap_admin_created", target=admin, after=snapshot(admin))
        session.commit()
