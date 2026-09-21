from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.database import db_session
from app.core.security import normalize_email
from app.core.time import utcnow
from app.models import AuditEvent, AuthSession, GitHubConnection, Project, Scan, User
from app.schemas import UserPatch
from app.services.audit import audit, public_user, snapshot
from app.services.auth import active_admin_count
from app.services.email import send_email, send_token_email

router = APIRouter(prefix="/admin", tags=["admin"])


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
    audit(db, request, "user_profile_updated", actor=actor, target=target, before=before, after=snapshot(target))
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
    audit(db, request, action, actor=actor, target=target, before=before, after=snapshot(target))
    send_email(
        db,
        target,
        template,
        subject,
        f"<p>Your VERITAS account status is now: {new_status.replace('_', ' ')}.</p>",
    )
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


@router.get("/audit-events")
def list_audit_events(
    actor_id: str | None = None,
    target_id: str | None = None,
    action: str | None = None,
    page: int = 1,
    page_size: int = 50,
    _: User = Depends(require_admin),
    db: Session = Depends(db_session),
):
    query = select(AuditEvent)
    if actor_id:
        query = query.where(AuditEvent.actor_user_id == actor_id)
    if target_id:
        query = query.where(AuditEvent.target_user_id == target_id)
    if action:
        query = query.where(AuditEvent.action == action)
    limit = min(max(page_size, 1), 100)
    events = list(
        db.scalars(query.order_by(AuditEvent.created_at.desc()).offset((max(page, 1) - 1) * limit).limit(limit))
    )
    return {
        "items": [
            {
                "id": event.id,
                "actor_user_id": event.actor_user_id,
                "target_user_id": event.target_user_id,
                "action": event.action,
                "before_state": event.before_state,
                "after_state": event.after_state,
                "created_at": event.created_at,
            }
            for event in events
        ]
    }
