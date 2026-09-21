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
    """Add profile columns to existing SQLite databases created before this phase."""
    inspector = inspect(db.engine)
    if "users" not in inspector.get_table_names():
        return
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
