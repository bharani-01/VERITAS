from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.database import db_session
from app.core.security import normalize_email, token_hash
from app.core.time import ensure_utc, is_expired, utcnow
from app.models import AuditEvent, AuthSession, GitHubConnection, HttpRequestEvent, Project, Scan, User
from app.schemas import UserPatch
from app.services.audit import audit, audit_broadcaster, audit_severity, public_user, serialize_audit_event, snapshot
from app.services.auth import active_admin_count
from app.services.email import send_account_status, send_token_email
from app.services.host_fs import list_dir, list_mounts, normalize_root, resolve_download
from app.services.http_traffic import serialize_http_event
from app.services.http_classifier import ATTACK_FAMILIES
from app.services.security_ai import analyze_http_security

router = APIRouter(prefix="/admin", tags=["admin"])


def _minute_key(dt: datetime) -> str:
    """Stable UTC minute bucket key (avoids naive vs aware isoformat mismatches)."""
    u = ensure_utc(dt).replace(second=0, microsecond=0)
    return u.strftime("%Y-%m-%dT%H:%M:00Z")


@router.get("/dashboard")
def admin_dashboard(_: User = Depends(require_admin), db: Session = Depends(db_session)):
    """Identity + Phase 2 workspace totals."""
    status_rows = db.execute(select(User.status, func.count()).group_by(User.status)).all()
    by_status = {status: count for status, count in status_rows}
    total = sum(by_status.values())
    pending_approval = list(
        db.scalars(
            select(User)
            .where(User.status == "pending_approval")
            .order_by(User.created_at.desc())
            .limit(8)
        )
    )
    recent_events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(10)))
    return {
        "totals": {
            "users": total,
            "active": by_status.get("active", 0),
            "pending_approval": by_status.get("pending_approval", 0),
            "pending_verification": by_status.get("pending_verification", 0),
            "deactivated": by_status.get("deactivated", 0),
            "rejected": by_status.get("rejected", 0),
            "admins": db.scalar(select(func.count()).select_from(User).where(User.role == "admin")) or 0,
            "projects": db.scalar(select(func.count()).select_from(Project)) or 0,
            "scans": db.scalar(select(func.count()).select_from(Scan)) or 0,
            "github_connections": db.scalar(
                select(func.count()).select_from(GitHubConnection).where(GitHubConnection.revoked_at.is_(None))
            )
            or 0,
        },
        "pending_approval": [public_user(user) for user in pending_approval],
        "recent_events": [
            {
                "id": event.id,
                "action": event.action,
                "actor_user_id": event.actor_user_id,
                "target_user_id": event.target_user_id,
                "created_at": event.created_at,
            }
            for event in recent_events
        ],
    }


@router.get("/users")
def list_users(
    q: str | None = None,
    role: str | None = None,
    account_status: str | None = None,
    page: int = 1,
    page_size: int = 25,
    _: User = Depends(require_admin),
    db: Session = Depends(db_session),
):
    page = max(page, 1)
    page_size = min(max(page_size, 1), 100)
    query = select(User)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.where(
            (User.email.ilike(pattern)) | (User.display_name.ilike(pattern)) | (User.username.ilike(pattern))
        )
    if role:
        query = query.where(User.role == role)
    if account_status:
        query = query.where(User.status == account_status)
    items = list(db.scalars(query.order_by(User.created_at.desc()).offset((page - 1) * page_size).limit(page_size)))
    return {"items": [public_user(user) for user in items], "page": page, "page_size": page_size}


@router.get("/users/{user_id}")
def get_user(user_id: str, _: User = Depends(require_admin), db: Session = Depends(db_session)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    events = list(
        db.scalars(
            select(AuditEvent)
            .where((AuditEvent.target_user_id == user_id) | (AuditEvent.actor_user_id == user_id))
            .order_by(AuditEvent.created_at.desc())
            .limit(100)
        )
    )
    return {
        "user": public_user(user),
        "audit_events": [
            {
                "action": event.action,
                "created_at": event.created_at,
                "before_state": event.before_state,
                "after_state": event.after_state,
            }
            for event in events
        ],
    }


@router.patch("/users/{user_id}")
def patch_user(
    user_id: str,
    body: UserPatch,
    request: Request,
    actor: User = Depends(require_admin),
    db: Session = Depends(db_session),
):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    if body.role and target.id == actor.id:
        raise HTTPException(status_code=400, detail="Administrators cannot change their own role.")
    before = snapshot(target)
    if body.display_name is not None:
        target.display_name = body.display_name.strip()
    if body.role is not None:
        if target.role == "admin" and body.role != "admin" and target.status == "active" and active_admin_count(db) <= 1:
            raise HTTPException(status_code=400, detail="The final active administrator cannot be demoted.")
        target.role = body.role
    if body.email is not None and normalize_email(str(body.email)) != target.email:
        email = normalize_email(str(body.email))
        if db.scalar(select(User).where(User.email == email, User.id != target.id)):
            raise HTTPException(status_code=409, detail="Email address is already in use.")
        target.email = email
        target.email_verified_at = None
        target.status = "pending_verification"
        db.query(AuthSession).filter(AuthSession.user_id == target.id, AuthSession.revoked_at.is_(None)).update(
            {"revoked_at": utcnow()}
        )
        send_token_email(db, target, "verification")
    audit(db, request, "user_profile_updated", actor=actor, target=target, before=before, after=snapshot(target), status_code=200)
    db.commit()
    return {"user": public_user(target)}


def transition_user(
    user_id: str,
    new_status: str,
    action: str,
    template: str,
    subject: str,
    actor: User,
    request: Request,
    db: Session,
) -> dict:
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    before = snapshot(target)
    if new_status == "active":
        if not target.email_verified_at:
            raise HTTPException(status_code=400, detail="Only verified accounts can be approved.")
        target.approved_at = utcnow()
        target.approved_by_user_id = actor.id
        target.deactivated_at = None
    if new_status == "deactivated":
        if target.role == "admin" and target.status == "active" and active_admin_count(db) <= 1:
            raise HTTPException(status_code=400, detail="The final active administrator cannot be deactivated.")
        target.deactivated_at = utcnow()
        db.query(AuthSession).filter(AuthSession.user_id == target.id, AuthSession.revoked_at.is_(None)).update(
            {"revoked_at": utcnow()}
        )
    target.status = new_status
    audit(db, request, action, actor=actor, target=target, before=before, after=snapshot(target), status_code=200)
    send_account_status(db, target, new_status)
    db.commit()
    return {"user": public_user(target)}


@router.post("/users/{user_id}/approve")
def approve_user(user_id: str, request: Request, actor: User = Depends(require_admin), db: Session = Depends(db_session)):
    return transition_user(
        user_id, "active", "user_approved", "account_approved", "Your VERITAS account is approved", actor, request, db
    )


@router.post("/users/{user_id}/reject")
def reject_user(user_id: str, request: Request, actor: User = Depends(require_admin), db: Session = Depends(db_session)):
    return transition_user(
        user_id, "rejected", "user_rejected", "account_rejected", "VERITAS account update", actor, request, db
    )


@router.post("/users/{user_id}/deactivate")
def deactivate_user(
    user_id: str, request: Request, actor: User = Depends(require_admin), db: Session = Depends(db_session)
):
    return transition_user(
        user_id,
        "deactivated",
        "user_deactivated",
        "account_deactivated",
        "Your VERITAS account was deactivated",
        actor,
        request,
        db,
    )


@router.post("/users/{user_id}/reactivate")
def reactivate_user(
    user_id: str, request: Request, actor: User = Depends(require_admin), db: Session = Depends(db_session)
):
    target = db.get(User, user_id)
    if not target or not target.email_verified_at:
        raise HTTPException(status_code=400, detail="Only previously verified users can be reactivated.")
    return transition_user(
        user_id,
        "active",
        "user_reactivated",
        "account_reactivated",
        "Your VERITAS account was reactivated",
        actor,
        request,
        db,
    )


_serialize_audit_event = serialize_audit_event


@router.websocket("/audit-events/ws")
async def audit_events_ws(
    websocket: WebSocket,
    session: str | None = None,
    db: Session = Depends(db_session),
):
    """Real-time WebSocket endpoint streaming audit events instantly to connected admin consoles."""
    cookie_token = websocket.cookies.get("veritas_session") or session
    user = None
    if cookie_token:
        auth_row = db.scalar(
            select(AuthSession).where(
                AuthSession.token_hash == token_hash(cookie_token),
                AuthSession.revoked_at.is_(None),
            )
        )
        if auth_row and not is_expired(auth_row.expires_at):
            candidate = db.get(User, auth_row.user_id)
            if candidate and candidate.status == "active" and candidate.role == "admin":
                user = candidate

    if not user:
        await websocket.close(code=1008)
        return

    await audit_broadcaster.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "message": "Subscribed to live audit events"})
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        audit_broadcaster.disconnect(websocket)


@router.get("/audit-events")
def list_audit_events(
    actor_id: str | None = None,
    target_id: str | None = None,
    action: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 50,
    since: str | None = None,
    _: User = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Append-only audit feed for administrators. Supports filters and live polling via `since`."""
    query = select(AuditEvent)
    if actor_id:
        query = query.where(AuditEvent.actor_user_id == actor_id)
    if target_id:
        query = query.where(AuditEvent.target_user_id == target_id)
    if action:
        query = query.where(AuditEvent.action == action)
    if category in ("attacks", "security"):
        query = query.where(
            or_(
                AuditEvent.action.like("api_sqli%"),
                AuditEvent.action.like("api_xss%"),
                AuditEvent.action.like("api_cmd%"),
                AuditEvent.action.like("api_path%"),
                AuditEvent.action.like("api_ssrf%"),
                AuditEvent.action.like("api_ssti%"),
                AuditEvent.action.like("api_open_redirect%"),
                AuditEvent.action.like("api_header%"),
                AuditEvent.action.like("api_csrf%"),
                AuditEvent.action.like("api_scanner%"),
                AuditEvent.action.like("api_auth_anomaly%"),
                AuditEvent.action.in_(["login_failed", "login_blocked_status", "rate_limited"]),
            )
        )
    elif category == "api":
        query = query.where(AuditEvent.action == "api_request")
    elif category == "auth":
        query = query.where(
            AuditEvent.action.in_(
                [
                    "login_succeeded",
                    "login_failed",
                    "login_blocked_status",
                    "logout",
                    "user_signed_up",
                    "email_verified",
                    "verification_resent",
                    "password_reset_requested",
                    "password_reset_completed",
                ]
            )
        )
    elif category == "auth_failures":
        query = query.where(
            AuditEvent.action.in_(["login_failed", "login_blocked_status", "rate_limited", "api_auth_anomaly"])
        )
    elif category == "admin":
        query = query.where(
            or_(
                AuditEvent.action.like("user_%"),
                AuditEvent.action.in_(["fs_list", "fs_download"]),
            )
        )
    elif category == "workspace":
        query = query.where(
            AuditEvent.action.in_(
                [
                    "project_created",
                    "project_updated",
                    "project_deleted",
                    "scan_started",
                    "github_connected",
                    "github_disconnected",
                    "github_oauth_failed",
                    "github_repo_attached",
                    "github_repo_rejected",
                ]
            )
        )
    # Always suppress internal frontend polling telemetry from the audit feed
    query = query.where(
        ~AuditEvent.context_json.like('%"/admin/audit-stats"%'),
        ~AuditEvent.context_json.like('%"/admin/rate-limits"%'),
        ~AuditEvent.context_json.like('%"/admin/security-analyze"%'),
    )
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid since timestamp.") from None
        query = query.where(AuditEvent.created_at > since_dt)

    limit = min(max(page_size, 1), 200)
    page = max(page, 1)
    # Severity is derived at serialize time; when filtering, over-fetch then filter in Python.
    if severity:
        events_all = list(db.scalars(query.order_by(AuditEvent.created_at.desc()).limit(500)))
        user_ids = {uid for event in events_all for uid in (event.actor_user_id, event.target_user_id) if uid}
        users: dict[str, User] = {}
        if user_ids:
            users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(list(user_ids)))).all()}
        serialized = [_serialize_audit_event(event, users) for event in events_all]
        filtered = [item for item in serialized if item.get("severity") == severity]
        total = len(filtered)
        start = (page - 1) * limit
        items = filtered[start : start + limit]
        return {
            "items": items,
            "page": page,
            "page_size": limit,
            "total": total,
            "server_time": utcnow(),
        }

    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    events = list(db.scalars(query.order_by(AuditEvent.created_at.desc()).offset((page - 1) * limit).limit(limit)))

    user_ids = {uid for event in events for uid in (event.actor_user_id, event.target_user_id) if uid}
    users: dict[str, User] = {}
    if user_ids:
        users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(list(user_ids)))).all()}

    return {
        "items": [_serialize_audit_event(event, users) for event in events],
        "page": page,
        "page_size": limit,
        "total": total,
        "server_time": utcnow(),
    }


@router.get("/audit-stats")
def get_audit_stats(_: User = Depends(require_admin), db: Session = Depends(db_session)):
    """KPI metrics for the audit console across 24h and 7d horizons."""
    now = utcnow()
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)

    poll_exclude = and_(
        ~AuditEvent.context_json.like('%"/admin/audit-stats"%'),
        ~AuditEvent.context_json.like('%"/admin/rate-limits"%'),
        ~AuditEvent.context_json.like('%"/admin/security-analyze"%'),
    )

    total_24h = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff_24h, poll_exclude)) or 0
    total_7d = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff_7d, poll_exclude)) or 0

    attack_filter = or_(
        AuditEvent.action.like("api_sqli%"),
        AuditEvent.action.like("api_xss%"),
        AuditEvent.action.like("api_cmd%"),
        AuditEvent.action.like("api_path%"),
        AuditEvent.action.like("api_ssrf%"),
        AuditEvent.action.like("api_ssti%"),
        AuditEvent.action.like("api_open_redirect%"),
        AuditEvent.action.like("api_header%"),
        AuditEvent.action.like("api_csrf%"),
        AuditEvent.action.like("api_scanner%"),
        AuditEvent.action.like("api_auth_anomaly%"),
    )
    attacks_24h = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff_24h, attack_filter)) or 0
    attacks_7d = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff_7d, attack_filter)) or 0

    failures_filter = AuditEvent.action.in_(["login_failed", "login_blocked_status", "rate_limited", "api_auth_anomaly"])
    failures_24h = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff_24h, failures_filter)) or 0
    failures_7d = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff_7d, failures_filter)) or 0

    unique_ips_24h = db.scalar(select(func.count(func.distinct(AuditEvent.ip_address))).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff_24h, AuditEvent.ip_address.is_not(None))) or 0
    unique_ips_7d = db.scalar(select(func.count(func.distinct(AuditEvent.ip_address))).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff_7d, AuditEvent.ip_address.is_not(None))) or 0

    http_24h = db.scalar(select(func.count()).select_from(HttpRequestEvent).where(HttpRequestEvent.created_at >= cutoff_24h)) or 0
    http_7d = db.scalar(select(func.count()).select_from(HttpRequestEvent).where(HttpRequestEvent.created_at >= cutoff_7d)) or 0

    return {
        "timeframe_24h": {
            "total_events": total_24h,
            "http_requests": http_24h or total_24h,
            "attacks_flagged": attacks_24h,
            "auth_failures": failures_24h,
            "unique_ips": unique_ips_24h,
        },
        "timeframe_7d": {
            "total_events": total_7d,
            "http_requests": http_7d or total_7d,
            "attacks_flagged": attacks_7d,
            "auth_failures": failures_7d,
            "unique_ips": unique_ips_7d,
        },
        "server_time": now,
    }


@router.get("/http-requests")
def list_http_requests(
    severity: str | None = None,
    classification: str | None = None,
    flagged: bool = False,
    q: str | None = None,
    page: int = 1,
    page_size: int = 50,
    since: str | None = None,
    _: User = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Live HTTP telemetry feed (metadata only)."""
    query = select(HttpRequestEvent)
    if severity:
        query = query.where(HttpRequestEvent.severity == severity)
    if classification:
        query = query.where(HttpRequestEvent.classification == classification)
    elif flagged:
        query = query.where(HttpRequestEvent.classification != "clean")
    if q and q.strip():
        pattern = f"%{q.strip()}%"
        query = query.where(HttpRequestEvent.path.ilike(pattern))
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid since timestamp.") from None
        query = query.where(HttpRequestEvent.created_at > since_dt)

    limit = min(max(page_size, 1), 100)
    page = max(page, 1)
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    events = list(
        db.scalars(query.order_by(HttpRequestEvent.created_at.desc()).offset((page - 1) * limit).limit(limit))
    )
    return {
        "items": [serialize_http_event(event) for event in events],
        "page": page,
        "page_size": limit,
        "total": total,
        "has_more": page * limit < total,
        "server_time": utcnow(),
    }


@router.get("/security-overview")
def security_overview(_: User = Depends(require_admin), db: Session = Depends(db_session)):
    """Aggregates for the admin Security dashboard (live Safe/Warning/Critical)."""
    now = utcnow()
    window_15 = now - timedelta(minutes=15)
    window_60 = now - timedelta(minutes=60)

    recent_15 = list(
        db.scalars(select(HttpRequestEvent).where(HttpRequestEvent.created_at >= window_15))
    )
    recent_60 = list(
        db.scalars(
            select(HttpRequestEvent)
            .where(HttpRequestEvent.created_at >= window_60)
            .order_by(HttpRequestEvent.created_at.asc())
        )
    )

    by_severity: dict[str, int] = defaultdict(int)
    by_class: dict[str, int] = defaultdict(int)
    for event in recent_15:
        by_severity[event.severity] += 1
        by_class[event.classification] += 1

    critical_n = by_severity.get("critical", 0)
    high_n = by_severity.get("high", 0)
    medium_n = by_severity.get("medium", 0)
    # weak_headers alone should not flip the whole board to warning
    hard_families = tuple(f for f in ATTACK_FAMILIES if f != "weak_headers")
    suspect_n = sum(by_class.get(k, 0) for k in hard_families)

    if critical_n > 0 or by_class.get("sqli", 0) > 0 or by_class.get("cmd_inject", 0) > 0:
        status = "critical"
        reason = f"{critical_n or suspect_n} critical / exploit-class signal(s) in the last 15 minutes"
    elif high_n > 0 or medium_n > 0 or suspect_n > 0:
        status = "warning"
        reason = f"{suspect_n or high_n + medium_n} elevated request(s) in the last 15 minutes"
    else:
        status = "safe"
        reason = "No suspicious HTTP patterns in the last 15 minutes"

    # 1-minute buckets for the last hour (UTC-normalized keys)
    counts_by_minute: dict[str, int] = defaultdict(int)
    for event in recent_60:
        counts_by_minute[_minute_key(event.created_at)] += 1
    buckets = []
    base = ensure_utc(window_60).replace(second=0, microsecond=0)
    for i in range(60):
        start = base + timedelta(minutes=i)
        key = _minute_key(start)
        buckets.append({"t": key, "count": counts_by_minute.get(key, 0)})

    suspicious = list(
        db.scalars(
            select(HttpRequestEvent)
            .where(
                HttpRequestEvent.created_at >= window_15,
                HttpRequestEvent.classification != "clean",
            )
            .order_by(HttpRequestEvent.created_at.desc())
            .limit(20)
        )
    )
    if len(suspicious) < 20:
        extra = list(
            db.scalars(
                select(HttpRequestEvent)
                .where(
                    HttpRequestEvent.created_at >= window_15,
                    HttpRequestEvent.severity.in_(["critical", "high", "medium"]),
                )
                .order_by(HttpRequestEvent.created_at.desc())
                .limit(20)
            )
        )
        seen = {e.id for e in suspicious}
        for e in extra:
            if e.id not in seen:
                suspicious.append(e)
            if len(suspicious) >= 20:
                break

    hit_families = [k for k in ATTACK_FAMILIES if by_class.get(k, 0) > 0]

    user_count = db.scalar(select(func.count()).select_from(User)) or 0
    audit_15 = (
        db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= window_15)) or 0
    )

    by_classification = {"clean": by_class.get("clean", 0)}
    for fam in ATTACK_FAMILIES:
        by_classification[fam] = by_class.get(fam, 0)

    return {
        "status": status,
        "reason": reason,
        "window_minutes": 15,
        "totals_15m": {
            "requests": len(recent_15),
            "suspicious": suspect_n,
            "by_severity": {
                "info": by_severity.get("info", 0),
                "low": by_severity.get("low", 0),
                "medium": by_severity.get("medium", 0),
                "high": by_severity.get("high", 0),
                "critical": by_severity.get("critical", 0),
            },
            "by_classification": by_classification,
        },
        "volume_60m": buckets,
        "recent_suspicious": [serialize_http_event(e) for e in suspicious[:20]],
        "hit_families": hit_families,
        "modules": {
            "user_system": {"users": user_count, "audit_events_15m": audit_15},
            "http_collection": {"requests_15m": len(recent_15), "requests_60m": len(recent_60)},
            "detection": {"suspicious_15m": suspect_n},
        },
        "server_time": now,
    }


@router.post("/security-analyze")
def security_analyze(_: User = Depends(require_admin), db: Session = Depends(db_session)):
    """AI agent: analyze recent HTTP telemetry and suggest countermeasures (Groq, fail-open)."""
    now = utcnow()
    window_15 = now - timedelta(minutes=15)

    # Full-window aggregates (same scope as the Security dashboard 15m totals)
    all_15 = list(
        db.scalars(select(HttpRequestEvent).where(HttpRequestEvent.created_at >= window_15))
    )
    by_severity: dict[str, int] = defaultdict(int)
    by_class: dict[str, int] = defaultdict(int)
    for event in all_15:
        by_severity[event.severity] += 1
        by_class[event.classification] += 1

    # Newest subset only — keeps the Groq prompt small
    sample_rows = sorted(all_15, key=lambda e: e.created_at or now, reverse=True)[:40]
    sample = []
    for event in sample_rows:
        sample.append(
            {
                "method": event.method,
                "path": (event.path or "")[:200],
                "status_code": event.status_code,
                "classification": event.classification,
                "severity": event.severity,
                "signals": (event.signals or "")[:300],
                "ip": event.ip_address,
            }
        )

    hard_families = tuple(f for f in ATTACK_FAMILIES if f != "weak_headers")
    suspicious = sum(by_class.get(k, 0) for k in hard_families)

    context = {
        "window": "last_15_minutes",
        "request_count": len(all_15),
        "suspicious_count": suspicious,
        "by_classification": dict(by_class),
        "by_severity": dict(by_severity),
        "sample_requests": sample,
        "sample_note": f"Showing {len(sample)} newest of {len(all_15)} requests in window",
    }
    result = analyze_http_security(context)
    result["analyzed_at"] = now
    result["sample_size"] = len(sample)
    result["request_count"] = len(all_15)
    return result


@router.get("/fs/mounts")
def fs_mounts(request: Request, actor: User = Depends(require_admin), db: Session = Depends(db_session)):
    """List real mounted disks available for the admin Files browser."""
    mounts = list_mounts()
    audit(
        db,
        request,
        "fs_list",
        actor=actor,
        after={"op": "mounts", "count": len(mounts)},
        status_code=200,
    )
    db.commit()
    return {"mounts": mounts, "server_time": utcnow()}


@router.get("/fs/list")
def fs_list(
    request: Request,
    root: str = "/",
    path: str = "",
    limit: int = 500,
    offset: int = 0,
    actor: User = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """List directory entries under an allowed mount root."""
    try:
        root_norm = normalize_root(root)
        data = list_dir(root_norm, path, limit=limit, offset=offset)
    except HTTPException as exc:
        audit(
            db,
            request,
            "fs_list",
            actor=actor,
            after={"op": "list", "root": root, "path": path, "error": exc.detail},
            status_code=exc.status_code,
        )
        db.commit()
        raise
    audit(
        db,
        request,
        "fs_list",
        actor=actor,
        after={
            "op": "list",
            "root": data.get("root"),
            "path": data.get("path"),
            "total": data.get("total"),
        },
        status_code=200,
    )
    db.commit()
    data["server_time"] = utcnow()
    return data


@router.get("/fs/download")
def fs_download(
    request: Request,
    root: str = "/",
    path: str = "",
    actor: User = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Download a single file from an allowed mount (secret paths blocked)."""
    try:
        root_norm = normalize_root(root)
        file_path = resolve_download(root_norm, path)
    except HTTPException as exc:
        audit(
            db,
            request,
            "fs_download",
            actor=actor,
            after={"op": "download", "root": root, "path": path, "error": exc.detail},
            status_code=exc.status_code,
        )
        db.commit()
        raise
    audit(
        db,
        request,
        "fs_download",
        actor=actor,
        after={
            "op": "download",
            "root": root_norm,
            "path": path,
            "name": file_path.name,
            "size": file_path.stat().st_size,
        },
        status_code=200,
    )
    db.commit()
    return FileResponse(
        path=str(file_path),
        filename=file_path.name,
        media_type="application/octet-stream",
    )


@router.get("/rate-limits")
def get_rate_limits(_: User = Depends(require_admin)):
    """Returns active rate limiting rules, configurations, and trigger statistics."""
    from app.core.rate_limit import rate_limiter

    return {
        "enabled": True,
        "rules": rate_limiter.get_rules_info(),
        "total_throttled": sum(rate_limiter.stats.values()),
        "active_buckets": len(rate_limiter.events),
    }
