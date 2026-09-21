from __future__ import annotations

import json
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.time import utcnow
from app.models import Project, Scan, User
from app.services import github as github_svc


def public_project(project: Project) -> dict:
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description or "",
        "github_repo_id": project.github_repo_id,
        "github_repo_full_name": project.github_repo_full_name,
        "github_default_branch": project.github_default_branch,
        "github_html_url": project.github_html_url,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
    }


def public_scan(scan: Scan, project_name: str | None = None) -> dict:
    summary = None
    if scan.summary_json:
        try:
            summary = json.loads(scan.summary_json)
        except json.JSONDecodeError:
            summary = None
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "project_name": project_name,
        "target": scan.target,
        "source": scan.source,
        "status": scan.status,
        "summary": summary,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "created_at": scan.created_at,
    }


def get_owned_project(db: Session, user: User, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if not project or project.owner_user_id != user.id:
        raise HTTPException(status_code=404, detail="Project not found.")
    return project


def list_projects(db: Session, user: User) -> list[Project]:
    return list(
        db.scalars(select(Project).where(Project.owner_user_id == user.id).order_by(Project.updated_at.desc()))
    )


def create_project(
    db: Session,
    user: User,
    *,
    name: str,
    description: str = "",
    github_repo_id: int | None = None,
) -> Project:
    project = Project(
        owner_user_id=user.id,
        name=name.strip(),
        description=(description or "").strip(),
    )
    if github_repo_id is not None:
        repo = github_svc.verify_owned_repo(db, user, github_repo_id)
        project.github_repo_id = int(repo["id"])
        project.github_repo_full_name = repo["full_name"]
        project.github_default_branch = repo.get("default_branch")
        project.github_html_url = repo.get("html_url")
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def update_project(
    db: Session,
    user: User,
    project_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    github_repo_id: int | None = None,
    clear_github: bool = False,
) -> Project:
    project = get_owned_project(db, user, project_id)
    if name is not None:
        project.name = name.strip()
    if description is not None:
        project.description = description.strip()
    if clear_github:
        project.github_repo_id = None
        project.github_repo_full_name = None
        project.github_default_branch = None
        project.github_html_url = None
    elif github_repo_id is not None:
        repo = github_svc.verify_owned_repo(db, user, github_repo_id)
        project.github_repo_id = int(repo["id"])
        project.github_repo_full_name = repo["full_name"]
        project.github_default_branch = repo.get("default_branch")
        project.github_html_url = repo.get("html_url")
    project.updated_at = utcnow()
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def delete_project(db: Session, user: User, project_id: str) -> None:
    project = get_owned_project(db, user, project_id)
    scans = list(db.scalars(select(Scan).where(Scan.project_id == project.id)))
    for scan in scans:
        db.delete(scan)
    db.delete(project)
    db.commit()


def list_scans(db: Session, user: User, *, project_id: str | None = None, limit: int = 50) -> list[tuple[Scan, str]]:
    query = (
        select(Scan, Project.name)
        .join(Project, Scan.project_id == Project.id)
        .where(Project.owner_user_id == user.id)
    )
    if project_id:
        query = query.where(Scan.project_id == project_id)
    rows = db.execute(query.order_by(Scan.created_at.desc()).limit(min(max(limit, 1), 100))).all()
    return [(scan, name) for scan, name in rows]


def get_owned_scan(db: Session, user: User, scan_id: str) -> tuple[Scan, Project]:
    row = db.execute(
        select(Scan, Project)
        .join(Project, Scan.project_id == Project.id)
        .where(Scan.id == scan_id, Project.owner_user_id == user.id)
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return row[0], row[1]


def create_scan(db: Session, user: User, project_id: str, target: str | None = None) -> Scan:
    project = get_owned_project(db, user, project_id)
    source = "manual"
    resolved_target = (target or "").strip()
    if not resolved_target and project.github_repo_full_name:
        resolved_target = project.github_repo_full_name
        source = "github_repo"
    if not resolved_target:
        raise HTTPException(status_code=400, detail="Scan target is required when the project has no linked repository.")
    scan = Scan(
        project_id=project.id,
        created_by_user_id=user.id,
        target=resolved_target[:512],
        source=source,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    # Phase 2 stub: immediately advance lifecycle without a real engine.
    return run_stub_scan(db, scan)


def run_stub_scan(db: Session, scan: Scan) -> Scan:
    """Mark a scan queued → running → completed with empty findings (Phase 2 stub)."""
    now = utcnow()
    scan.status = "running"
    scan.started_at = now
    scan.summary_json = None
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan.status = "completed"
    scan.finished_at = utcnow()
    scan.summary_json = json.dumps(
        {
            "findings_count": 0,
            "engine": "stub",
            "note": "Phase 2 stub — no vulnerability engine attached.",
        }
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def workspace_dashboard(db: Session, user: User) -> dict:
    projects = list_projects(db, user)
    week_ago = utcnow() - timedelta(days=7)
    scans_week = (
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .join(Project, Scan.project_id == Project.id)
            .where(Project.owner_user_id == user.id, Scan.created_at >= week_ago)
        )
        or 0
    )
    recent = list_scans(db, user, limit=8)
    github = github_svc.connection_status(db, user)
    return {
        "totals": {
            "projects": len(projects),
            "scans_this_week": scans_week,
        },
        "github": github,
        "recent_scans": [public_scan(scan, name) for scan, name in recent],
        "projects": [public_project(p) for p in projects[:6]],
    }
