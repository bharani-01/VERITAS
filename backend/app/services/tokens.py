from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.security import token_hash
from app.core.time import utcnow
from app.models import OneTimeToken, User


def issue_token(db: Session, user: User, token_type: str) -> str:
    db.query(OneTimeToken).filter(
        OneTimeToken.user_id == user.id,
        OneTimeToken.token_type == token_type,
        OneTimeToken.used_at.is_(None),
    ).update({"used_at": utcnow()})
    raw = secrets.token_urlsafe(32)
    db.add(
        OneTimeToken(
            user_id=user.id,
            token_type=token_type,
            token_hash=token_hash(raw),
            expires_at=utcnow() + timedelta(minutes=30),
        )
    )
    return raw
