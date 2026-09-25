from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import PUBLIC_APP_URL
from app.core.database import db_session
from app.models import User
from app.schemas.workspace import FindingStatusUpdate, FindingSuppressCreate, ProjectCreate, ProjectUpdate, ScanCreate
from app.services import github as github_svc
from app.services import projects as project_svc
from app.services.audit import audit

router = APIRouter(prefix="/workspace", tags=["workspace"])


def _project_snapshot(project) -> dict:
    return {
        "project_id": project.id,
        "name": project.name,
        "github_repo_id": project.github_repo_id,
        "github_repo_full_name": project.github_repo_full_name,
    }


@router.get("/dashboard")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    return project_svc.workspace_dashboard(db, user)


@router.get("/projects")
def list_projects(user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    return {"items": [project_svc.public_project(p) for p in project_svc.list_projects(db, user)]}


@router.post("/projects", status_code=201)
def create_project(
    body: ProjectCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    try:
        project = project_svc.create_project(
            db,
            user,
            name=body.name,
            description=body.description,
            github_repo_id=body.github_repo_id,
            security_level=body.security_level,
            auto_scan_on_push=body.auto_scan_on_push,
            auto_scan_branch=body.auto_scan_branch,
        )
    except HTTPException as exc:
        if body.github_repo_id is not None and "owned by your connected GitHub" in str(exc.detail):
            audit(
                db,
                request,
                "github_repo_rejected",
                actor=user,
                target=user,
                after={"github_repo_id": body.github_repo_id, "reason": str(exc.detail)},
                status_code=exc.status_code,
            )
            db.commit()
        raise
    after = _project_snapshot(project)
    audit(db, request, "project_created", actor=user, target=user, after=after, status_code=201)
    if project.github_repo_id is not None:
        audit(db, request, "github_repo_attached", actor=user, target=user, after=after, status_code=201)
    db.commit()
    return {"project": project_svc.public_project(project)}


@router.get("/projects/{project_id}")
def get_project(project_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    project = project_svc.get_owned_project(db, user, project_id)
    return {"project": project_svc.public_project(project)}


@router.patch("/projects/{project_id}")
def patch_project(
    project_id: str,
    body: ProjectUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    before_project = project_svc.get_owned_project(db, user, project_id)
    before = _project_snapshot(before_project)
    try:
        project = project_svc.update_project(
            db,
            user,
            project_id,
            name=body.name,
            description=body.description,
            github_repo_id=body.github_repo_id,
            clear_github=body.clear_github,
            security_level=body.security_level,
            base_url=body.base_url,
            criticality=body.criticality,
            notify_email_default=body.notify_email_default,
            notify_in_app_default=body.notify_in_app_default,
            auto_scan_on_push=body.auto_scan_on_push,
            auto_scan_branch=body.auto_scan_branch,
            scan_options=body.scan_options,
        )
    except HTTPException as exc:
        if body.github_repo_id is not None and "owned by your connected GitHub" in str(exc.detail):
            audit(
                db,
                request,
                "github_repo_rejected",
                actor=user,
                target=user,
                after={"project_id": project_id, "github_repo_id": body.github_repo_id, "reason": str(exc.detail)},
                status_code=exc.status_code,
            )
            db.commit()
        raise
    after = _project_snapshot(project)
    audit(db, request, "project_updated", actor=user, target=user, before=before, after=after, status_code=200)
    if body.github_repo_id is not None and project.github_repo_id is not None:
        audit(db, request, "github_repo_attached", actor=user, target=user, before=before, after=after, status_code=200)
    db.commit()
    return {"project": project_svc.public_project(project)}


@router.delete("/projects/{project_id}", status_code=204)
def remove_project(
    project_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    project = project_svc.get_owned_project(db, user, project_id)
    before = _project_snapshot(project)
    project_svc.delete_project(db, user, project_id)
    audit(db, request, "project_deleted", actor=user, target=user, before=before, status_code=204)
    db.commit()
    return None


@router.get("/projects/{project_id}/scans")
def list_project_scans(project_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    project_svc.get_owned_project(db, user, project_id)
    rows = project_svc.list_scans(db, user, project_id=project_id)
    return {"items": [project_svc.public_scan(scan, name) for scan, name in rows]}


@router.post("/projects/{project_id}/scans", status_code=201)
def create_project_scan(
    project_id: str,
    body: ScanCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    scan = project_svc.create_scan(
        db,
        user,
        project_id,
        target=body.target,
        security_level=body.security_level,
        scan_mode=body.scan_mode,
        scan_scope=body.scan_scope,
        notify_email=body.notify_email,
        notify_in_app=body.notify_in_app,
        ref=body.ref,
        engines=body.engines,
        path_excludes=body.path_excludes,
        fail_severity=body.fail_severity,
        code_review=body.code_review,
    )
    project = project_svc.get_owned_project(db, user, project_id)
    audit(
        db,
        request,
        "scan_started",
        actor=user,
        target=user,
        after={
            "scan_id": scan.id,
            "project_id": project.id,
            "project_name": project.name,
            "target": scan.target,
            "source": scan.source,
            "status": scan.status,
            "scan_mode": scan.scan_mode,
            "security_level": scan.security_level,
            "eta_seconds": scan.eta_seconds,
        },
        status_code=201,
    )
    db.commit()
    return {"scan": project_svc.public_scan(scan, project.name)}


@router.get("/projects/{project_id}/scans/{scan_id}/findings")
@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
    project_id: str | None = None,
):
    items = project_svc.list_findings(db, user, scan_id)
    if project_id is not None:
        project_svc.get_owned_project(db, user, project_id)
    return {"items": [project_svc.public_finding(f) for f in items], "total": len(items)}


@router.patch("/findings/{finding_id}")
def patch_finding(
    finding_id: str,
    body: FindingStatusUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    finding = project_svc.update_finding_status(db, user, finding_id, status=body.status)
    return {"finding": project_svc.public_finding(finding)}


@router.post("/findings/{finding_id}/suppress")
def suppress_finding(
    finding_id: str,
    body: FindingSuppressCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    finding = project_svc.suppress_finding(db, user, finding_id, reason=body.reason)
    return {"finding": project_svc.public_finding(finding)}


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    scan = project_svc.cancel_scan(db, user, scan_id)
    return {"scan": project_svc.public_scan(scan)}


@router.get("/projects/{project_id}/scans/compare")
def compare_scans(
    project_id: str,
    a: str = Query(...),
    b: str = Query(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    return project_svc.compare_scans(db, user, project_id, scan_a=a, scan_b=b)


@router.get("/projects/{project_id}/git-refs")
def project_git_refs(project_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    return project_svc.list_project_git_refs(db, user, project_id)


@router.get("/scans")
def list_scans(
    limit: int = Query(default=50, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    rows = project_svc.list_scans(db, user, limit=limit)
    return {"items": [project_svc.public_scan(scan, name) for scan, name in rows]}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    scan, project = project_svc.get_owned_scan(db, user, scan_id)
    return {"scan": project_svc.public_scan(scan, project.name)}


@router.post("/scans/{scan_id}/share")
def share_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    scan = project_svc.ensure_share_token(db, user, scan_id)
    return {
        "share_token": scan.share_token,
        "share_url": f"{PUBLIC_APP_URL}/report/{scan.share_token}",
        "scan": project_svc.public_scan(scan),
    }


@router.delete("/scans/{scan_id}/share")
def unshare_scan(scan_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    scan = project_svc.revoke_share_token(db, user, scan_id)
    return {"shared": False, "scan": project_svc.public_scan(scan)}


@router.get("/github/status")
def github_status(user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    return github_svc.connection_status(db, user)


@router.get("/github/authorize")
def github_authorize(user: User = Depends(get_current_user)):
    url = github_svc.begin_oauth(user)
    return RedirectResponse(url=url, status_code=302)


@router.get("/github/callback")
def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    db: Session = Depends(db_session),
):
    if not code or not state:
        return RedirectResponse(url=f"{PUBLIC_APP_URL}/user/projects/new?error=missing_code", status_code=302)
    try:
        conn = github_svc.complete_oauth(db, code=code, state=state)
        user = db.get(User, conn.user_id)
        if user:
            audit(
                db,
                request,
                "github_connected",
                actor=user,
                target=user,
                after={"github_login": conn.github_login, "github_user_id": conn.github_user_id},
                status_code=302,
            )
            db.commit()
    except HTTPException as exc:
        detail = str(exc.detail).replace(" ", "_")[:80]
        # Best-effort failure audit without a resolved user (state may be invalid).
        audit(db, request, "github_oauth_failed", after={"reason": str(exc.detail)[:200]}, status_code=302)
        db.commit()
        return RedirectResponse(url=f"{PUBLIC_APP_URL}/user/projects/new?error={detail}", status_code=302)
    except Exception:
        audit(db, request, "github_oauth_failed", after={"reason": "oauth_failed"}, status_code=302)
        db.commit()
        return RedirectResponse(url=f"{PUBLIC_APP_URL}/user/projects/new?error=oauth_failed", status_code=302)
    return RedirectResponse(url=f"{PUBLIC_APP_URL}/user/projects/new?connected=1", status_code=302)


@router.post("/github/disconnect")
def github_disconnect(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    status = github_svc.connection_status(db, user)
    github_svc.disconnect(db, user)
    audit(
        db,
        request,
        "github_disconnected",
        actor=user,
        target=user,
        before={"github_login": status.get("github_login"), "connected": status.get("connected")},
        status_code=200,
    )
    db.commit()
    return {"ok": True}


@router.get("/github/repos")
def github_repos(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=30, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    return {"items": github_svc.list_owned_repos(db, user, page=page, per_page=per_page)}


@router.get("/github/repos/{repo_id}/refs")
def github_repo_refs(repo_id: int, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    """Branches/tags for an owned repo (used by New project Advanced before create)."""
    meta = github_svc.verify_owned_repo(db, user, repo_id)
    refs = github_svc.list_repo_refs(db, user, meta["full_name"])
    refs["default"] = meta.get("default_branch")
    return refs
