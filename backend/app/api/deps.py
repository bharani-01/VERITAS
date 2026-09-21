from __future__ import annotations

from fastapi import Cookie, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import db_session
from app.core.security import token_hash
from app.core.time import is_expired, utcnow
from app.models import AuthSession, User


def get_current_user(
    request: Request,
    veritas_session: str | None = Cookie(default=None),
    db: Session = Depends(db_session),
) -> User:
    if not veritas_session:
        raise HTTPException(status_code=401, detail="Authentication required.")
    session = db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == token_hash(veritas_session),
            AuthSession.revoked_at.is_(None),
        )
    )
    if not session or is_expired(session.expires_at):
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")
    user = db.get(User, session.user_id)
    if not user or user.status != "active":
        raise HTTPException(status_code=401, detail="Account is not active.")
    session.last_seen_at = utcnow()
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user
