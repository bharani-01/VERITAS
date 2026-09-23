from __future__ import annotations

import json
import logging
import secrets
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import (
    APP_ENV,
    PUBLIC_APP_URL,
    SCAN_CONCURRENT_LIMIT,
    SCAN_RATE_LIMIT,
    SCAN_RATE_WINDOW_SECONDS,
)
from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.rate_limit import rate_limiter
from app.core.time import utcnow
from app.models import Finding, FindingSuppression, Project, Scan, User
from app.services import github as github_svc
from app.services.engines.normalize import finding_fingerprint, public_repo_path
from app.services.scan_runner import enqueue_scan, estimate_eta_seconds, run_scan_job

FINDING_STATUSES = {"open", "triage", "fixed", "false_positive"}
logger = logging.getLogger(__name__)


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
        "auto_scan_on_push": bool(getattr(project, "auto_scan_on_push", False)),
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
        "scan_scope": getattr(scan, "scan_scope", None) or "full",
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
        "cancel_requested": bool(getattr(scan, "cancel_requested", False)),
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
        "fingerprint": finding.fingerprint,
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


def _webhook_callback_url() -> str:
    return f"{PUBLIC_APP_URL.rstrip('/')}/webhooks/github"


def _clear_webhook_fields(project: Project) -> None:
    project.github_webhook_id = None
    project.github_webhook_secret = None


def sync_project_webhook(db: Session, user: User, project: Project) -> None:
    """Ensure GitHub webhook exists iff auto_scan_on_push and a repo are set."""
    want = bool(project.auto_scan_on_push) and bool(project.github_repo_full_name)
    full_name = project.github_repo_full_name or ""
    hook_id = getattr(project, "github_webhook_id", None)

    if not want:
        if hook_id and full_name:
            try:
                github_svc.delete_repo_webhook(db, user, full_name=full_name, hook_id=int(hook_id))
            except Exception as exc:  # noqa: BLE001 — best-effort cleanup
                logger.warning("webhook delete failed: %s", str(exc)[:200])
        _clear_webhook_fields(project)
        return

    secret = secrets.token_urlsafe(32)
    try:
        new_id = github_svc.create_repo_push_webhook(
            db,
            user,
            full_name=full_name,
            secret=secret,
            webhook_url=_webhook_callback_url(),
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("webhook create failed: %s", str(exc)[:200])
        raise HTTPException(status_code=400, detail="Could not register GitHub push webhook.") from exc

    # Remove previous hook if recreate
    if hook_id and int(hook_id) != int(new_id) and full_name:
        try:
            github_svc.delete_repo_webhook(db, user, full_name=full_name, hook_id=int(hook_id))
        except Exception:  # noqa: BLE001
            pass

    project.github_webhook_id = int(new_id)
    project.github_webhook_secret = encrypt_secret(secret)


def create_project(
    db: Session,
    user: User,
    *,
    name: str,
    description: str = "",
    github_repo_id: int | None = None,
    security_level: str = "standard",
    auto_scan_on_push: bool = False,
) -> Project:
    level = security_level if security_level in {"basic", "standard", "strict"} else "standard"
    project = Project(
        owner_user_id=user.id,
        name=name.strip(),
        description=(description or "").strip(),
        security_level=level,
        auto_scan_on_push=bool(auto_scan_on_push),
    )
    if github_repo_id is not None:
        repo = github_svc.verify_owned_repo(db, user, github_repo_id)
        project.github_repo_id = int(repo["id"])
        project.github_repo_full_name = repo["full_name"]
        project.github_default_branch = repo.get("default_branch")
        project.github_html_url = repo.get("html_url")
    if project.auto_scan_on_push and not project.github_repo_full_name:
        raise HTTPException(status_code=400, detail="Auto-scan on push requires a linked GitHub repository.")
    if project.auto_scan_on_push:
        sync_project_webhook(db, user, project)
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
    auto_scan_on_push: bool | None = None,
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
    if auto_scan_on_push is not None:
        project.auto_scan_on_push = bool(auto_scan_on_push)

    repo_changed = False
    if clear_github:
        if project.github_webhook_id and project.github_repo_full_name:
            try:
                github_svc.delete_repo_webhook(
                    db, user, full_name=project.github_repo_full_name, hook_id=int(project.github_webhook_id)
                )
            except Exception:  # noqa: BLE001
                pass
        project.github_repo_id = None
        project.github_repo_full_name = None
        project.github_default_branch = None
        project.github_html_url = None
        _clear_webhook_fields(project)
        project.auto_scan_on_push = False
        repo_changed = True
    elif github_repo_id is not None:
        # Tear down old hook before switching repos
        if project.github_webhook_id and project.github_repo_full_name:
            try:
                github_svc.delete_repo_webhook(
                    db, user, full_name=project.github_repo_full_name, hook_id=int(project.github_webhook_id)
                )
            except Exception:  # noqa: BLE001
                pass
            _clear_webhook_fields(project)
        repo = github_svc.verify_owned_repo(db, user, github_repo_id)
        project.github_repo_id = int(repo["id"])
        project.github_repo_full_name = repo["full_name"]
        project.github_default_branch = repo.get("default_branch")
        project.github_html_url = repo.get("html_url")
        repo_changed = True

    if project.auto_scan_on_push and not project.github_repo_full_name:
        raise HTTPException(status_code=400, detail="Auto-scan on push requires a linked GitHub repository.")

    if auto_scan_on_push is not None or repo_changed:
        sync_project_webhook(db, user, project)

    project.updated_at = utcnow()
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def delete_project(db: Session, user: User, project_id: str) -> None:
    project = get_owned_project(db, user, project_id)
    if project.github_webhook_id and project.github_repo_full_name:
        try:
            github_svc.delete_repo_webhook(
                db, user, full_name=project.github_repo_full_name, hook_id=int(project.github_webhook_id)
            )
        except Exception:  # noqa: BLE001
            pass
    scans = list(db.scalars(select(Scan).where(Scan.project_id == project.id)))
    for scan in scans:
        for finding in db.scalars(select(Finding).where(Finding.scan_id == scan.id)):
            db.delete(finding)
        db.delete(scan)
    for row in db.scalars(select(FindingSuppression).where(FindingSuppression.project_id == project.id)):
        db.delete(row)
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
    scan_scope: str | None = None,
    notify_email: bool | None = None,
    notify_in_app: bool | None = None,
    ref: str | None = None,
    source: str | None = None,
    commit_sha: str | None = None,
    commit_message: str | None = None,
    commit_author: str | None = None,
    enforce_quota: bool = True,
) -> Scan:
    project = get_owned_project(db, user, project_id)

    # Quotas: concurrent + hourly rate (skip in test for deterministic suites).
    if enforce_quota and APP_ENV != "test":
        active = (
            db.scalar(
                select(func.count())
                .select_from(Scan)
                .where(
                    Scan.created_by_user_id == user.id,
                    Scan.status.in_(("queued", "running")),
                )
            )
            or 0
        )
        if active >= SCAN_CONCURRENT_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f"Too many scans in progress (limit {SCAN_CONCURRENT_LIMIT}). Wait for one to finish.",
            )
        try:
            rate_limiter.check(f"scan:{user.id}", SCAN_RATE_LIMIT, SCAN_RATE_WINDOW_SECONDS)
        except HTTPException:
            raise HTTPException(
                status_code=429,
                detail=f"Scan rate limit reached ({SCAN_RATE_LIMIT} per hour). Try again later.",
            ) from None

    resolved_source = (source or "").strip() or "manual"
    resolved_target = (target or "").strip()
    if not resolved_target and project.github_repo_full_name:
        resolved_target = project.github_repo_full_name
        if resolved_source == "manual":
            resolved_source = "github_repo"
    if not resolved_target:
        raise HTTPException(status_code=400, detail="Scan target is required when the project has no linked repository.")

    level = security_level or project.security_level or "standard"
    if level not in {"basic", "standard", "strict"}:
        raise HTTPException(status_code=400, detail="Invalid security_level.")
    mode = scan_mode or ("rules_plus_ai" if level == "strict" else "rules_only")
    if mode not in {"rules_only", "rules_plus_ai"}:
        raise HTTPException(status_code=400, detail="Invalid scan_mode.")
    scope = (scan_scope or "full").strip().lower()
    if scope not in {"full", "changed"}:
        raise HTTPException(status_code=400, detail="Invalid scan_scope.")
    if scope == "changed" and resolved_source not in {"github_repo", "github_push"}:
        raise HTTPException(status_code=400, detail="Changed-files scans require a linked GitHub repository.")

    sha = (commit_sha or "").strip() or None
    short = sha[:12] if sha else None

    eta = estimate_eta_seconds(
        security_level=level,
        scan_mode=mode,
        has_github=bool(project.github_repo_full_name),
    )
    scan = Scan(
        project_id=project.id,
        created_by_user_id=user.id,
        target=resolved_target[:512],
        source=resolved_source[:32],
        status="queued",
        security_level=level,
        scan_mode=mode,
        scan_scope=scope,
        ref=(ref or "").strip() or None,
        commit_sha=sha,
        commit_short=short,
        commit_message=(commit_message or "").strip()[:512] or None,
        commit_author=(commit_author or "").strip()[:256] or None,
        eta_seconds=eta,
        cancel_requested=False,
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


def handle_github_push_event(db: Session, *, payload: dict) -> dict:
    """Create a scan for push to a project's default branch. Returns status dict."""
    repo = payload.get("repository") or {}
    repo_id = repo.get("id")
    if repo_id is None:
        return {"ok": True, "skipped": "no_repo"}

    ref = str(payload.get("ref") or "")
    if not ref.startswith("refs/heads/"):
        return {"ok": True, "skipped": "not_branch"}
    branch = ref.removeprefix("refs/heads/")

    project = db.scalar(
        select(Project).where(
            Project.github_repo_id == int(repo_id),
            Project.auto_scan_on_push.is_(True),
        )
    )
    if not project:
        return {"ok": True, "skipped": "no_project"}

    default_branch = (project.github_default_branch or repo.get("default_branch") or "main").strip()
    if branch != default_branch:
        return {"ok": True, "skipped": "not_default_branch", "branch": branch}

    head = payload.get("after") or ((payload.get("head_commit") or {}).get("id"))
    if not head or head == "0000000000000000000000000000000000000000":
        return {"ok": True, "skipped": "no_commit"}

    existing = db.scalar(
        select(Scan).where(Scan.project_id == project.id, Scan.commit_sha == head).limit(1)
    )
    if existing:
        return {"ok": True, "skipped": "duplicate", "scan_id": existing.id}

    owner = db.get(User, project.owner_user_id)
    if not owner:
        return {"ok": False, "error": "owner_missing"}

    head_commit = payload.get("head_commit") or {}
    try:
        scan = create_scan(
            db,
            owner,
            project.id,
            source="github_push",
            ref=branch,
            commit_sha=head,
            commit_message=head_commit.get("message"),
            commit_author=(head_commit.get("author") or {}).get("name")
            or (head_commit.get("author") or {}).get("username"),
            enforce_quota=True,
        )
    except HTTPException as exc:
        if exc.status_code == 429:
            return {"ok": True, "skipped": "quota", "detail": exc.detail}
        raise

    return {"ok": True, "scan_id": scan.id, "status": scan.status}


def cancel_scan(db: Session, user: User, scan_id: str) -> Scan:
    scan, _project = get_owned_scan(db, user, scan_id)
    if scan.status not in {"queued", "running"}:
        raise HTTPException(status_code=400, detail="Only queued or running scans can be cancelled.")
    scan.cancel_requested = True
    if scan.status == "queued":
        scan.status = "cancelled"
        scan.finished_at = utcnow()
        scan.progress_json = json.dumps(
            {"phase": "cancelled", "label": "Cancelled", "percent": 100, "eta_remaining_seconds": 0}
        )
        scan.eta_seconds = 0
        scan.error_message = "Scan cancelled by user."
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def update_finding_status(db: Session, user: User, finding_id: str, *, status: str) -> Finding:
    status = (status or "").strip().lower()
    if status not in FINDING_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid finding status.")
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    get_owned_scan(db, user, finding.scan_id)
    finding.status = status
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def suppress_finding(db: Session, user: User, finding_id: str, *, reason: str | None = None) -> Finding:
    finding = update_finding_status(db, user, finding_id, status="false_positive")
    scan, project = get_owned_scan(db, user, finding.scan_id)
    fp = finding.fingerprint or finding_fingerprint(
        engine=finding.engine,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        line_start=finding.line_start,
        title=finding.title,
    )
    finding.fingerprint = fp
    existing = db.scalar(
        select(FindingSuppression).where(
            FindingSuppression.project_id == project.id,
            FindingSuppression.fingerprint == fp,
        )
    )
    if not existing:
        db.add(
            FindingSuppression(
                project_id=project.id,
                fingerprint=fp,
                reason=(reason or "").strip()[:512] or None,
                created_by_user_id=user.id,
            )
        )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def compare_scans(db: Session, user: User, project_id: str, *, scan_a: str, scan_b: str) -> dict:
    project = get_owned_project(db, user, project_id)
    a, pa = get_owned_scan(db, user, scan_a)
    b, pb = get_owned_scan(db, user, scan_b)
    if pa.id != project.id or pb.id != project.id:
        raise HTTPException(status_code=400, detail="Both scans must belong to this project.")
    if a.status != "completed" or b.status != "completed":
        raise HTTPException(status_code=400, detail="Compare requires two completed scans.")

    def _map(scan: Scan) -> dict[str, Finding]:
        out: dict[str, Finding] = {}
        for f in db.scalars(select(Finding).where(Finding.scan_id == scan.id)):
            fp = f.fingerprint or finding_fingerprint(
                engine=f.engine,
                rule_id=f.rule_id,
                file_path=f.file_path,
                line_start=f.line_start,
                title=f.title,
            )
            out[fp] = f
        return out

    ma, mb = _map(a), _map(b)
    keys_a, keys_b = set(ma), set(mb)
    added = [public_finding(mb[k]) for k in sorted(keys_b - keys_a)]
    removed = [public_finding(ma[k]) for k in sorted(keys_a - keys_b)]
    unchanged = []
    for k in sorted(keys_a & keys_b):
        unchanged.append({"fingerprint": k, "a": public_finding(ma[k]), "b": public_finding(mb[k])})
    return {
        "project_id": project.id,
        "scan_a": public_scan(a, project.name),
        "scan_b": public_scan(b, project.name),
        "added": added,
        "removed": removed,
        "unchanged_count": len(unchanged),
        "unchanged": unchanged[:200],
        "counts": {"added": len(added), "removed": len(removed), "unchanged": len(unchanged)},
    }


def list_project_git_refs(db: Session, user: User, project_id: str) -> dict:
    project = get_owned_project(db, user, project_id)
    if not project.github_repo_full_name:
        raise HTTPException(status_code=400, detail="Project has no linked GitHub repository.")
    return github_svc.list_repo_refs(db, user, project.github_repo_full_name)


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
