from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session
from starlette.websockets import WebSocket

from app.models import AuditEvent, User
from app.services.geoip import lookup_ip


class AuditBroadcaster:
    """Manages active WebSocket connections from admin consoles and broadcasts audit events live."""

    def __init__(self) -> None:
        self._active_connections: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._active_connections.discard(websocket)

    async def _broadcast_async(self, data: dict[str, Any]) -> None:
        if not self._active_connections:
            return
        dead: list[WebSocket] = []
        for ws in list(self._active_connections):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._active_connections.discard(ws)

    def broadcast(self, data: dict[str, Any]) -> None:
        if not self._active_connections:
            return
        try:
            loop = self._loop
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(self._broadcast_async(data), loop)
            else:
                try:
                    cur_loop = asyncio.get_running_loop()
                    cur_loop.create_task(self._broadcast_async(data))
                except RuntimeError:
                    pass
        except Exception:
            pass


audit_broadcaster = AuditBroadcaster()

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
    "fs_list": "Admin listed host filesystem",
    "fs_download": "Admin downloaded a host file",
    "api_request": "API HTTP request",
    "api_sqli": "SQL injection detected in API request",
    "api_xss": "XSS attack pattern detected in API request",
    "api_cmd_inject": "Command injection attempt detected",
    "api_path_traversal": "Path traversal attempt detected",
    "api_ssrf": "SSRF attack pattern detected",
    "api_ssti": "Server-side template injection attempt",
    "api_open_redirect": "Open redirect parameter detected",
    "api_header_abuse": "Header injection / CRLF abuse detected",
    "api_csrf": "CSRF origin / referer anomaly detected",
    "api_scanner": "Security scanner probing detected",
    "api_auth_anomaly": "Authentication path anomaly detected",
    "api_weak_headers": "Weak security response headers detected",
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
    if action in _ACTION_SUMMARIES:
        return _ACTION_SUMMARIES[action]
    if action.startswith("api_"):
        kind = action[4:].replace("_", " ").upper()
        return f"API Security Event ({kind})"
    return action.replace("_", " ").capitalize()


def audit_severity(action: str, status_code: int | None = None) -> str:
    """Derive display severity for audit events."""
    if action in ("api_sqli", "api_cmd_inject"):
        return "critical"
    if action in ("api_xss", "api_path_traversal", "api_ssrf", "api_ssti", "api_header_abuse", "api_csrf"):
        return "high"
    if action in ("api_scanner", "api_open_redirect", "api_auth_anomaly"):
        return "medium"
    if action == "api_weak_headers":
        return "low"
    if action == "api_request":
        if status_code is not None:
            if status_code >= 500:
                return "high"
            if status_code >= 400:
                return "medium"
        return "info"

    if action in ("login_failed", "login_blocked_status", "github_oauth_failed", "github_repo_rejected"):
        return "high"
    if action == "rate_limited":
        return "medium"
    if action in ("user_rejected", "user_deactivated"):
        return "medium"
    if action in ("logout", "project_deleted", "github_disconnected"):
        return "low"
    if action == "fs_download":
        return "medium"
    if action == "fs_list":
        return "low"
    if status_code is not None:
        if status_code >= 500:
            return "medium"
        if status_code >= 400:
            return "low"
    if action in (
        "login_succeeded",
        "user_approved",
        "user_reactivated",
        "github_connected",
        "project_created",
        "scan_started",
        "email_verified",
    ):
        return "info"
    return "info"


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
    payload: str | dict | None = None,
) -> None:
    if request:
        try:
            request.state.audit_logged = True
            if not payload:
                payload = getattr(request.state, "audit_payload", None)
        except Exception:
            pass

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
    payload_str: str | None = None
    if payload:
        payload_str = json.dumps(payload, indent=2) if isinstance(payload, (dict, list)) else str(payload)
        context["what"]["payload"] = payload_str
        context["payload"] = payload_str

    after_state = json.dumps(after) if after else payload_str

    event = AuditEvent(
        actor_user_id=actor.id if actor else None,
        target_user_id=target.id if target else None,
        action=action,
        before_state=json.dumps(before) if before else None,
        after_state=after_state,
        ip_address=ip_address,
        user_agent=user_agent,
        context_json=json.dumps(context),
    )
    db.add(event)

    try:
        users = {u.id: u for u in (actor, target) if u}
        serialized = serialize_audit_event(event, users)
        audit_broadcaster.broadcast({"type": "audit_event", "event": serialized})
    except Exception:
        pass


def record_audit_api_event(
    db: Session,
    *,
    request: Request | None,
    method: str,
    path: str,
    query: str | None,
    status_code: int,
    ip_address: str | None,
    user_agent: str | None,
    session_cookie: str | None,
    payload: str | None = None,
) -> None:
    from app.services.http_traffic import resolve_actor_id
    from app.services.http_classifier import classify_request

    actor_id = resolve_actor_id(db, session_cookie)
    actor_user = db.get(User, actor_id) if actor_id else None

    # Classify request with security heuristics
    classification, _, signals = classify_request(
        method=method,
        path=path,
        query=query,
        status_code=status_code,
        has_session_cookie=bool(session_cookie),
        origin=request.headers.get("origin") if request else None,
        referer=request.headers.get("referer") if request else None,
        request_host=request.headers.get("host") if request else None,
        user_agent=user_agent,
    )

    if classification != "clean":
        action = f"api_{classification}"
    else:
        action = "api_request"

    context = build_context(
        request=request,
        action=action,
        actor=actor_user,
        target=None,
        before=None,
        after=None,
        ip_address=ip_address,
        forwarded_for=None,
        user_agent=user_agent,
        status_code=status_code,
    )

    if signals:
        context["what"]["signals"] = signals
    if payload:
        context["what"]["payload"] = payload
        context["payload"] = payload

    event = AuditEvent(
        actor_user_id=actor_id,
        target_user_id=None,
        action=action,
        before_state=None,
        after_state=payload,
        ip_address=ip_address,
        user_agent=user_agent,
        context_json=json.dumps(context),
    )
    db.add(event)
    db.commit()

    try:
        users = {actor_user.id: actor_user} if actor_user else {}
        serialized = serialize_audit_event(event, users)
        audit_broadcaster.broadcast({"type": "audit_event", "event": serialized})
    except Exception:
        pass


def _user_label(user: User | None) -> dict | None:
    if not user:
        return None
    return {
        "id": user.id,
        "display_name": user.display_name,
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }


def _label_from_context(blob: dict | None) -> dict | None:
    if not blob or not isinstance(blob, dict):
        return None
    if not blob.get("id") and not blob.get("email") and not blob.get("display_name"):
        return None
    return {
        "id": blob.get("id"),
        "display_name": blob.get("display_name") or blob.get("email") or "Unknown",
        "username": blob.get("username"),
        "email": blob.get("email"),
        "role": blob.get("role"),
    }


def serialize_audit_event(event: AuditEvent, users: dict[str, Any] | None = None) -> dict[str, Any]:
    context = None
    if event.context_json:
        try:
            context = json.loads(event.context_json)
        except Exception:
            context = None

    users = users or {}
    actor = users.get(event.actor_user_id) if event.actor_user_id else None
    target = users.get(event.target_user_id) if event.target_user_id else None

    who = (context or {}).get("who") if isinstance(context, dict) else None
    how = (context or {}).get("how") if isinstance(context, dict) else None
    geo = (context or {}).get("where", {}).get("geo") if context else None
    summary = (context or {}).get("what", {}).get("summary") if context else None
    status_code = (how or {}).get("status_code") if isinstance(how, dict) else None

    actor_label = _user_label(actor) or _label_from_context((who or {}).get("actor") if isinstance(who, dict) else None)
    target_label = _user_label(target) or _label_from_context((who or {}).get("target") if isinstance(who, dict) else None)

    location_label = None
    if isinstance(geo, dict):
        location_label = geo.get("label")
        if not location_label and geo.get("skipped"):
            location_label = "Local network" if geo.get("reason") == "private_or_local" else "Unavailable"

    severity = audit_severity(event.action, status_code if isinstance(status_code, int) else None)

    payload = None
    if isinstance(context, dict):
        payload = context.get("what", {}).get("payload") or context.get("payload")
    if not payload and event.after_state and (event.action.startswith("api_") or not event.before_state):
        payload = event.after_state

    created_at_val = event.created_at
    created_at_iso = created_at_val.isoformat() if hasattr(created_at_val, "isoformat") else str(created_at_val)

    return {
        "id": event.id,
        "actor_user_id": event.actor_user_id,
        "target_user_id": event.target_user_id,
        "actor": actor_label,
        "target": target_label,
        "action": event.action,
        "summary": summary or event.action.replace("_", " "),
        "status_code": status_code,
        "severity": severity,
        "payload": payload,
        "before_state": event.before_state,
        "after_state": event.after_state,
        "ip_address": event.ip_address,
        "user_agent": event.user_agent,
        "location_label": location_label,
        "geo": geo,
        "context": context,
        "created_at": created_at_iso,
        "who": {
            "actor": actor_label,
            "target": target_label,
            "actor_is_admin": bool(
                (actor and getattr(actor, "role", None) == "admin")
                or (actor_label and actor_label.get("role") == "admin")
                or (isinstance(who, dict) and who.get("actor_is_admin"))
            ),
        },
        "what": {"action": event.action, "summary": summary or event.action.replace("_", " ")},
        "when": created_at_iso,
        "where": {
            "ip": event.ip_address,
            "location": location_label,
            "geo": geo,
        },
        "how": {
            "user_agent": event.user_agent,
            "method": (how or {}).get("method") if isinstance(how, dict) else None,
            "path": (how or {}).get("path") if isinstance(how, dict) else None,
            "status_code": status_code,
        },
    }

