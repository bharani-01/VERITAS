from __future__ import annotations

import json
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import APP_ENV
from app.core.time import utcnow
from app.models import Finding, Project, Scan, User
from app.services import github as github_svc
from app.services.engines.normalize import public_repo_path
from app.services.scan_runner import enqueue_scan, estimate_eta_seconds, run_scan_job


def public_project(project: Project) -> dict:
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description or "",
        "github_repo_id": project.github_repo_id,
        "github_repo_full_name": project.github_repo_full_name,
        "github_default_branch": project.github_default_branch,
        "github_html_url": project.github_html_url,
        "security_level": project.security_level or "standard",
        "base_url": project.base_url,
        "criticality": project.criticality or "medium",
        "notify_email_default": bool(project.notify_email_default),
        "notify_in_app_default": bool(project.notify_in_app_default),
        "created_at": project.created_at,
        "updated_at": project.updated_at,
    }


def _progress(scan: Scan) -> dict | None:
    if not scan.progress_json:
        return None
    try:
        return json.loads(scan.progress_json)
    except json.JSONDecodeError:
        return None


def _git_history(scan: Scan) -> list:
    if not scan.git_history_json:
        return []
    try:
        data = json.loads(scan.git_history_json)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def public_scan(scan: Scan, project_name: str | None = None) -> dict:
    summary = None
    if scan.summary_json:
        try:
            summary = json.loads(scan.summary_json)
        except json.JSONDecodeError:
            summary = None
    risk = None
    if scan.risk_summary_json:
        try:
            risk = json.loads(scan.risk_summary_json)
        except json.JSONDecodeError:
            risk = None
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "project_name": project_name,
        "target": scan.target,
        "source": scan.source,
        "status": scan.status,
        "security_level": scan.security_level or "standard",
        "scan_mode": scan.scan_mode or "rules_only",
        "ref": scan.ref,
        "commit_sha": scan.commit_sha,
        "commit_short": scan.commit_short,
        "commit_message": scan.commit_message,
        "commit_author": scan.commit_author,
        "git_history": _git_history(scan),
        "share_token": scan.share_token,
        "shared": bool(scan.share_token),
        "progress": _progress(scan),
        "eta_seconds": scan.eta_seconds,
        "error_message": scan.error_message,
        "summary": summary,
        "risk_summary": risk,
        "notify_email": bool(scan.notify_email),
        "notify_in_app": bool(scan.notify_in_app),
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "created_at": scan.created_at,
    }


def public_finding(finding: Finding) -> dict:
    countermeasures = None
    if finding.countermeasures_json:
        try:
            countermeasures = json.loads(finding.countermeasures_json)
        except json.JSONDecodeError:
            countermeasures = None

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "engine": finding.engine,
        "rule_id": finding.rule_id,
        "vuln_family": finding.vuln_family,
        "cwe": finding.cwe,
        "owasp_category": finding.owasp_category,
        "severity": finding.severity,
        "title": finding.title,
        "message": finding.message,
        "file_path": public_repo_path(finding.file_path),
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "snippet": finding.snippet,
        "risk_score": finding.risk_score,
        "status": finding.status,
        "ai_verdict": finding.ai_verdict,
        "ai_rationale": finding.ai_rationale,
        "countermeasures": countermeasures,
        "created_at": finding.created_at,
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
    security_level: str = "standard",
) -> Project:
    level = security_level if security_level in {"basic", "standard", "strict"} else "standard"
    project = Project(
        owner_user_id=user.id,
        name=name.strip(),
        description=(description or "").strip(),
        security_level=level,
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
    security_level: str | None = None,
    base_url: str | None = None,
    criticality: str | None = None,
    notify_email_default: bool | None = None,
    notify_in_app_default: bool | None = None,
) -> Project:
    project = get_owned_project(db, user, project_id)
    if name is not None:
        project.name = name.strip()
    if description is not None:
        project.description = description.strip()
    if security_level is not None:
        if security_level not in {"basic", "standard", "strict"}:
            raise HTTPException(status_code=400, detail="Invalid security_level.")
        project.security_level = security_level
    if base_url is not None:
        project.base_url = base_url.strip() or None
    if criticality is not None:
        if criticality not in {"low", "medium", "high"}:
            raise HTTPException(status_code=400, detail="Invalid criticality.")
        project.criticality = criticality
    if notify_email_default is not None:
        project.notify_email_default = notify_email_default
    if notify_in_app_default is not None:
        project.notify_in_app_default = notify_in_app_default
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
        for finding in db.scalars(select(Finding).where(Finding.scan_id == scan.id)):
            db.delete(finding)
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


def list_findings(db: Session, user: User, scan_id: str) -> list[Finding]:
    get_owned_scan(db, user, scan_id)
    return list(db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())))


def ensure_share_token(db: Session, user: User, scan_id: str) -> Scan:
    import secrets

    scan, _project = get_owned_scan(db, user, scan_id)
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=400, detail="Share is available after the scan finishes.")
    if not scan.share_token:
        scan.share_token = secrets.token_urlsafe(24)
        db.add(scan)
        db.commit()
        db.refresh(scan)
    return scan


def revoke_share_token(db: Session, user: User, scan_id: str) -> Scan:
    scan, _project = get_owned_scan(db, user, scan_id)
    scan.share_token = None
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_shared_report(db: Session, token: str) -> dict:
    scan = db.scalar(select(Scan).where(Scan.share_token == token))
    if not scan:
        raise HTTPException(status_code=404, detail="Shared report not found.")
    project = db.get(Project, scan.project_id)
    findings = list(
        db.scalars(select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.risk_score.desc()))
    )
    return {
        "scan": public_scan(scan, project.name if project else None),
        "project": {
            "name": project.name if project else "Project",
            "github_repo_full_name": project.github_repo_full_name if project else None,
            "github_html_url": project.github_html_url if project else None,
        },
        "items": [public_finding(f) for f in findings],
        "total": len(findings),
    }


def create_scan(
    db: Session,
    user: User,
    project_id: str,
    *,
    target: str | None = None,
    security_level: str | None = None,
    scan_mode: str | None = None,
    notify_email: bool | None = None,
    notify_in_app: bool | None = None,
    ref: str | None = None,
) -> Scan:
    project = get_owned_project(db, user, project_id)
    source = "manual"
    resolved_target = (target or "").strip()
    if not resolved_target and project.github_repo_full_name:
        resolved_target = project.github_repo_full_name
        source = "github_repo"
    if not resolved_target:
        raise HTTPException(status_code=400, detail="Scan target is required when the project has no linked repository.")

    level = security_level or project.security_level or "standard"
    if level not in {"basic", "standard", "strict"}:
        raise HTTPException(status_code=400, detail="Invalid security_level.")
    mode = scan_mode or ("rules_plus_ai" if level == "strict" else "rules_only")
    if mode not in {"rules_only", "rules_plus_ai"}:
        raise HTTPException(status_code=400, detail="Invalid scan_mode.")

    eta = estimate_eta_seconds(
        security_level=level,
        scan_mode=mode,
        has_github=bool(project.github_repo_full_name),
    )
    scan = Scan(
        project_id=project.id,
        created_by_user_id=user.id,
        target=resolved_target[:512],
        source=source,
        status="queued",
        security_level=level,
        scan_mode=mode,
        ref=(ref or "").strip() or None,
        eta_seconds=eta,
        progress_json=json.dumps(
            {"phase": "queued", "label": "Getting ready…", "percent": 0, "eta_remaining_seconds": eta}
        ),
        notify_email=project.notify_email_default if notify_email is None else notify_email,
        notify_in_app=project.notify_in_app_default if notify_in_app is None else notify_in_app,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    if APP_ENV == "test":
        run_scan_job(scan.id)
        db.refresh(scan)
    else:
        enqueue_scan(scan.id)
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
    findings_open = (
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(Project, Scan.project_id == Project.id)
            .where(Project.owner_user_id == user.id, Finding.status == "open")
        )
        or 0
    )
    recent = list_scans(db, user, limit=8)
    github = github_svc.connection_status(db, user)
    return {
        "totals": {
            "projects": len(projects),
            "scans_this_week": scans_week,
            "open_findings": findings_open,
        },
        "github": github,
        "recent_scans": [public_scan(scan, name) for scan, name in recent],
        "projects": [public_project(p) for p in projects[:6]],
    }
