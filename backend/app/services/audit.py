from __future__ import annotations

import json

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditEvent, User


def snapshot(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "username": user.username,
        "avatar": user.avatar,
        "role": user.role,
        "status": user.status,
    }


def public_user(user: User) -> dict:
    return {
        "id": user.id,
        "display_name": user.display_name,
        "username": user.username,
        "avatar": user.avatar or "slate",
        "email": user.email,
        "role": user.role,
        "status": user.status,
        "email_verified_at": user.email_verified_at,
        "force_password_reset": user.force_password_reset,
        "last_login_at": user.last_login_at,
    }


def audit(
    db: Session,
    request: Request | None,
    action: str,
    actor: User | None = None,
    target: User | None = None,
    before: dict | None = None,
    after: dict | None = None,
) -> None:
    db.add(
        AuditEvent(
            actor_user_id=actor.id if actor else None,
            target_user_id=target.id if target else None,
            action=action,
            before_state=json.dumps(before) if before else None,
            after_state=json.dumps(after) if after else None,
            ip_address=request.client.host if request and request.client else None,
            user_agent=(request.headers.get("user-agent") if request else None),
        )
    )
