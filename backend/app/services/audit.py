from __future__ import annotations

import json
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditEvent, User
from app.services.geoip import lookup_ip

_ACTION_SUMMARIES = {
    "login_succeeded": "Signed in successfully",
    "login_failed": "Failed sign-in attempt",
    "login_blocked_status": "Sign-in blocked by account status",
    "logout": "Signed out",
    "user_signed_up": "Created a new account",
    "email_verified": "Verified email address",
    "verification_resent": "Resent verification email",
    "password_reset_requested": "Requested password reset",
    "password_reset_completed": "Completed password reset",
    "profile_updated": "Updated own profile",
    "user_profile_updated": "Admin updated a user profile",
    "user_approved": "Admin approved a user",
    "user_rejected": "Admin rejected a user",
    "user_deactivated": "Admin deactivated a user",
    "user_reactivated": "Admin reactivated a user",
    "bootstrap_admin_created": "Bootstrap administrator created",
    "project_created": "Created a project",
    "project_updated": "Updated a project",
    "project_deleted": "Deleted a project",
    "scan_started": "Started a scan",
    "github_connected": "Connected GitHub",
    "github_disconnected": "Disconnected GitHub",
    "github_oauth_failed": "GitHub OAuth failed",
    "github_repo_attached": "Attached a GitHub repository",
    "github_repo_rejected": "Rejected foreign GitHub repository attach",
    "rate_limited": "Request rate limited",
}


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


def action_summary(action: str) -> str:
    return _ACTION_SUMMARIES.get(action, action.replace("_", " ").capitalize())


def _client_ip(request: Request | None) -> tuple[str | None, str | None]:
    if not request:
        return None, None
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip() or None
    direct = request.client.host if request.client else None
    # Prefer direct socket peer; keep forwarded as reported (untrusted unless reverse-proxy is configured).
    return direct or forwarded, forwarded


def _person_blob(user: User | None) -> dict[str, Any] | None:
    if not user:
        return None
    return {
        "id": user.id,
        "display_name": user.display_name,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "status": user.status,
    }


def build_context(
    *,
    request: Request | None,
    action: str,
    actor: User | None,
    target: User | None,
    before: dict | None,
    after: dict | None,
    ip_address: str | None,
    forwarded_for: str | None,
    user_agent: str | None,
    status_code: int | None,
) -> dict[str, Any]:
    geo = lookup_ip(ip_address)
    return {
        "who": {
            "actor": _person_blob(actor),
            "target": _person_blob(target),
            "actor_is_admin": bool(actor and actor.role == "admin"),
        },
        "what": {
            "action": action,
            "summary": action_summary(action),
            "before": before,
            "after": after,
        },
        "when": {
            # filled at read time from created_at; keep placeholder for completeness
            "source": "server",
        },
        "where": {
            "ip": ip_address,
            "forwarded_for": forwarded_for,
            "geo": geo,
        },
        "how": {
            "user_agent": user_agent,
            "method": request.method if request else None,
            "path": request.url.path if request else None,
            "status_code": status_code,
        },
    }


def audit(
    db: Session,
    request: Request | None,
    action: str,
    actor: User | None = None,
    target: User | None = None,
    before: dict | None = None,
    after: dict | None = None,
    status_code: int | None = None,
) -> None:
    ip_address, forwarded_for = _client_ip(request)
    user_agent = (request.headers.get("user-agent") if request else None)
    context = build_context(
        request=request,
        action=action,
        actor=actor,
        target=target,
        before=before,
        after=after,
        ip_address=ip_address,
        forwarded_for=forwarded_for,
        user_agent=user_agent,
        status_code=status_code,
    )
    db.add(
        AuditEvent(
            actor_user_id=actor.id if actor else None,
            target_user_id=target.id if target else None,
            action=action,
            before_state=json.dumps(before) if before else None,
            after_state=json.dumps(after) if after else None,
            ip_address=ip_address,
            user_agent=user_agent,
            context_json=json.dumps(context),
        )
    )
