from __future__ import annotations

import re

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import AVATAR_OPTIONS, USERNAME_RE, normalize_username
from app.models import User


def validate_username(value: str) -> str:
    username = normalize_username(value)
    if not USERNAME_RE.fullmatch(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3–32 characters, start with a letter, and use only lowercase letters, numbers, or underscores.",
        )
    return username


def validate_avatar(value: str) -> str:
    avatar = value.strip().lower()
    if avatar not in AVATAR_OPTIONS:
        raise HTTPException(status_code=400, detail="Choose a valid avatar.")
    return avatar


def allocate_username(db: Session, seed: str, exclude_user_id: str | None = None) -> str:
    base = re.sub(r"[^a-z0-9_]", "", seed.lower())
    if not base or not base[0].isalpha():
        base = f"user{base}"
    base = (base or "user")[:28]
    candidate = base
    index = 1
    while True:
        existing = db.scalar(select(User).where(User.username == candidate))
        if not existing or existing.id == exclude_user_id:
            return candidate
        index += 1
        candidate = f"{base}{index}"
