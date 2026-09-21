from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import PUBLIC_APP_URL
from app.core.database import db_session
from app.models import User
from app.schemas.workspace import ProjectCreate, ProjectUpdate, ScanCreate
from app.services import github as github_svc
from app.services import projects as project_svc

router = APIRouter(prefix="/workspace", tags=["workspace"])


@router.get("/dashboard")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    return project_svc.workspace_dashboard(db, user)


@router.get("/projects")
def list_projects(user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    return {"items": [project_svc.public_project(p) for p in project_svc.list_projects(db, user)]}


@router.post("/projects", status_code=201)
def create_project(
    body: ProjectCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    project = project_svc.create_project(
        db,
        user,
        name=body.name,
        description=body.description,
        github_repo_id=body.github_repo_id,
    )
    return {"project": project_svc.public_project(project)}


@router.get("/projects/{project_id}")
def get_project(project_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    project = project_svc.get_owned_project(db, user, project_id)
    return {"project": project_svc.public_project(project)}


@router.patch("/projects/{project_id}")
def patch_project(
    project_id: str,
    body: ProjectUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    project = project_svc.update_project(
        db,
        user,
        project_id,
        name=body.name,
        description=body.description,
        github_repo_id=body.github_repo_id,
        clear_github=body.clear_github,
    )
    return {"project": project_svc.public_project(project)}


@router.delete("/projects/{project_id}", status_code=204)
def remove_project(project_id: str, user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    project_svc.delete_project(db, user, project_id)
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
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    scan = project_svc.create_scan(db, user, project_id, target=body.target)
    project = project_svc.get_owned_project(db, user, project_id)
    return {"scan": project_svc.public_scan(scan, project.name)}


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
        return RedirectResponse(url=f"{PUBLIC_APP_URL}/user/integrations?error=missing_code", status_code=302)
    try:
        github_svc.complete_oauth(db, code=code, state=state)
    except HTTPException as exc:
        detail = str(exc.detail).replace(" ", "_")[:80]
        return RedirectResponse(url=f"{PUBLIC_APP_URL}/user/integrations?error={detail}", status_code=302)
    except Exception:
        return RedirectResponse(url=f"{PUBLIC_APP_URL}/user/integrations?error=oauth_failed", status_code=302)
    return RedirectResponse(url=f"{PUBLIC_APP_URL}/user/integrations?connected=1", status_code=302)


@router.post("/github/disconnect")
def github_disconnect(user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    github_svc.disconnect(db, user)
    return {"ok": True}


@router.get("/github/repos")
def github_repos(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=30, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    return {"items": github_svc.list_owned_repos(db, user, page=page, per_page=per_page)}
