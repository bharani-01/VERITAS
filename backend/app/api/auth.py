from __future__ import annotations

from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import COOKIE_SECURE, SESSION_TTL_HOURS
from app.core.database import db_session
from app.core.rate_limit import check_rate_limit
from app.core.security import normalize_email, password_hasher, token_hash
from app.core.time import is_expired, utcnow
from app.models import AuthSession, OneTimeToken, User
from app.schemas import EmailInput, LoginInput, ProfileUpdate, ResetInput, SignupInput, TokenInput
from app.api.deps import get_current_user
from app.services.audit import audit, public_user, snapshot
from app.services.auth import create_session
from app.services.email import send_admin_approval_required, send_password_changed, send_token_email
from app.services.profile import allocate_username, validate_avatar, validate_username

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", status_code=202)
def signup(body: SignupInput, request: Request, db: Session = Depends(db_session)):
    check_rate_limit(db, request, f"signup:{request.client.host if request.client else 'unknown'}", 5, 3600)
    email = normalize_email(str(body.email))
    if db.scalar(select(User).where(User.email == email)):
        return {"message": "If this email can be registered, a verification message has been sent."}
    user = User(
        display_name=body.display_name.strip(),
        username=allocate_username(db, email.split("@")[0] or body.display_name),
        avatar="slate",
        email=email,
        password_hash=password_hasher.hash(body.password),
    )
    db.add(user)
    db.flush()
    audit(db, request, "user_signed_up", target=user, after=snapshot(user), status_code=202)
    send_token_email(db, user, "verification")
    db.commit()
    return {"message": "If this email can be registered, a verification message has been sent."}


@router.post("/login")
def login(body: LoginInput, request: Request, response: Response, db: Session = Depends(db_session)):
    check_rate_limit(db, request, f"login:{request.client.host if request.client else 'unknown'}", 10, 900)
    user = db.scalar(select(User).where(User.email == normalize_email(str(body.email))))
    valid = False
    if user:
        try:
            valid = password_hasher.verify(user.password_hash, body.password)
        except VerifyMismatchError:
            valid = False
    if not user or not valid:
        audit(db, request, "login_failed", target=user, status_code=401)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if user.status != "active":
        labels = {
            "pending_verification": "Verify your email to continue.",
            "pending_approval": "Your account is awaiting administrator approval.",
            "rejected": "Your account is not approved for access.",
            "deactivated": "Your account has been deactivated.",
        }
        audit(db, request, "login_blocked_status", target=user, after={"status": user.status}, status_code=403)
        db.commit()
        raise HTTPException(status_code=403, detail=labels.get(user.status, "Your account is not active."))
    raw = create_session(db, user, request)
    user.last_login_at = utcnow()
    audit(db, request, "login_succeeded", actor=user, target=user, status_code=200)
    db.commit()
    response.set_cookie(
        "veritas_session",
        raw,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_TTL_HOURS * 3600,
        path="/",
    )
    return {"user": public_user(user)}


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    veritas_session: str | None = Cookie(default=None),
    db: Session = Depends(db_session),
):
    if veritas_session:
        session = db.scalar(
            select(AuthSession).where(
                AuthSession.token_hash == token_hash(veritas_session),
                AuthSession.revoked_at.is_(None),
            )
        )
        if session:
            session.revoked_at = utcnow()
            user = db.get(User, session.user_id)
            audit(db, request, "logout", actor=user, target=user, status_code=204)
            db.commit()
    response.delete_cookie("veritas_session", path="/")


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"user": public_user(user)}


def _update_profile(body: ProfileUpdate, request: Request, user: User, db: Session) -> dict:
    check_rate_limit(db, request, f"profile:{request.client.host if request.client else 'unknown'}", 20, 900)
    before = snapshot(user)
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    if body.username is not None:
        username = validate_username(body.username)
        conflict = db.scalar(select(User).where(User.username == username, User.id != user.id))
        if conflict:
            raise HTTPException(status_code=409, detail="That username is already taken.")
        user.username = username
    if body.avatar is not None:
        user.avatar = validate_avatar(body.avatar)
    audit(db, request, "profile_updated", actor=user, target=user, before=before, after=snapshot(user), status_code=200)
    db.commit()
    db.refresh(user)
    return {"user": public_user(user), "message": "Profile updated."}


@router.patch("/me")
@router.post("/me")
def update_me(
    body: ProfileUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    return _update_profile(body, request, user, db)


@router.post("/verify-email")
def verify_email(body: TokenInput, request: Request, db: Session = Depends(db_session)):
    check_rate_limit(db, request, f"verify:{request.client.host if request.client else 'unknown'}", 10, 900)
    record = db.scalar(
        select(OneTimeToken).where(
            OneTimeToken.token_type == "verification",
            OneTimeToken.token_hash == token_hash(body.token),
            OneTimeToken.used_at.is_(None),
        )
    )
    if not record or is_expired(record.expires_at):
        raise HTTPException(status_code=400, detail="This verification link is invalid or expired.")
    user = db.get(User, record.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="This verification link is invalid or expired.")
    before = snapshot(user)
    record.used_at = utcnow()
    user.email_verified_at = utcnow()
    user.status = "pending_approval"
    audit(db, request, "email_verified", target=user, before=before, after=snapshot(user), status_code=200)
    for admin in db.scalars(select(User).where(User.role == "admin", User.status == "active")):
        send_admin_approval_required(db, admin, user)
    db.commit()
    return {"message": "Email verified. Your account is awaiting administrator approval."}


@router.post("/resend-verification", status_code=202)
def resend_verification(body: EmailInput, request: Request, db: Session = Depends(db_session)):
    check_rate_limit(db, request, f"resend:{request.client.host if request.client else 'unknown'}", 3, 3600)
    user = db.scalar(select(User).where(User.email == normalize_email(str(body.email))))
    if user and user.status == "pending_verification":
        send_token_email(db, user, "verification")
        audit(db, request, "verification_resent", target=user, status_code=202)
        db.commit()
    return {"message": "If the account needs verification, a message has been sent."}


@router.post("/password-reset/request", status_code=202)
def password_reset_request(body: EmailInput, request: Request, db: Session = Depends(db_session)):
    check_rate_limit(db, request, f"reset:{request.client.host if request.client else 'unknown'}", 3, 3600)
    user = db.scalar(select(User).where(User.email == normalize_email(str(body.email))))
    if user and user.status == "active":
        send_token_email(db, user, "password_reset")
        audit(db, request, "password_reset_requested", target=user, status_code=202)
        db.commit()
    return {"message": "If an active account uses this email, a reset message has been sent."}


@router.post("/password-reset/confirm")
def password_reset_confirm(body: ResetInput, request: Request, db: Session = Depends(db_session)):
    check_rate_limit(db, request, f"reset-confirm:{request.client.host if request.client else 'unknown'}", 5, 900)
    record = db.scalar(
        select(OneTimeToken).where(
            OneTimeToken.token_type == "password_reset",
            OneTimeToken.token_hash == token_hash(body.token),
            OneTimeToken.used_at.is_(None),
        )
    )
    if not record or is_expired(record.expires_at):
        raise HTTPException(status_code=400, detail="This reset link is invalid or expired.")
    user = db.get(User, record.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="This reset link is invalid or expired.")
    record.used_at = utcnow()
    user.password_hash = password_hasher.hash(body.password)
    user.force_password_reset = False
    db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).update(
        {"revoked_at": utcnow()}
    )
    audit(db, request, "password_reset_completed", target=user, status_code=200)
    send_password_changed(db, user)
    db.commit()
    return {"message": "Password updated. Please sign in again."}
