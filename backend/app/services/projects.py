from __future__ import annotations

import json
import logging
import secrets
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import case, desc, func, select
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
from app.core.time import ensure_utc, utcnow
from app.models import (
    Finding,
    FindingSuppression,
    Project,
    ProjectMember,
    Scan,
    ScanSbomArtifact,
    User,
)
from app.services import github as github_svc
from app.services.audit import record_audit_event
from app.services.compliance import compute_finding_sla
from app.services.engines import ALL_ENGINES, DEFAULT_ENGINES
from app.services.engines.normalize import finding_fingerprint, public_repo_path
from app.services.engines.trivy_sbom import analyze_cyclonedx_sbom
from app.services.scan_runner import enqueue_scan, estimate_eta_seconds, run_scan_job

FINDING_STATUSES = {"open", "triage", "fixed", "false_positive"}
VALID_FINDING_STATUS = FINDING_STATUSES
VALID_MEMBER_ROLES = {"security_lead", "developer", "auditor"}
_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")
logger = logging.getLogger(__name__)



def _empty_severity() -> dict[str, int]:
    return {k: 0 for k in _SEVERITY_KEYS}


def _normalize_severity_counts(raw: dict | None) -> dict[str, int]:
    out = _empty_severity()
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        k = str(key or "").lower()
        if k in out:
            try:
                out[k] = max(0, int(value))
            except (TypeError, ValueError):
                out[k] = 0
    return out


def _dashboard_charts(db: Session, user: User) -> dict:
    """Compare previous scan runs + open-finding distributions for the user dashboard."""
    owned = Project.owner_user_id == user.id

    # Look back over recent finished scans; prefer ones that still have finding rows.
    # (Newest commits can be clean redeploys while open findings live on older scans.)
    candidates = db.execute(
        select(Scan, Project.name, func.count(Finding.id))
        .join(Project, Scan.project_id == Project.id)
        .outerjoin(Finding, Finding.scan_id == Scan.id)
        .where(owned, Scan.status.in_(("completed", "failed")))
        .group_by(Scan.id, Project.name)
        .order_by(Scan.created_at.desc())
        .limit(120)
    ).all()
    with_findings = [(scan, name) for scan, name, count in candidates if int(count or 0) > 0][:30]
    if len(with_findings) >= 2:
        run_rows = list(reversed(with_findings))
    else:
        run_rows = list(reversed([(scan, name) for scan, name, _ in candidates[:30]]))
    run_ids = [scan.id for scan, _ in run_rows]

    # Prefer live Finding rows — older summaries often omit by_severity / findings_count.
    sev_by_scan: dict[str, dict[str, int]] = {sid: _empty_severity() for sid in run_ids}
    total_by_scan: dict[str, int] = {sid: 0 for sid in run_ids}
    family_by_scan: dict[str, dict[str, int]] = {sid: {} for sid in run_ids}
    if run_ids:
        for scan_id, severity, count in db.execute(
            select(Finding.scan_id, Finding.severity, func.count())
            .where(Finding.scan_id.in_(run_ids))
            .group_by(Finding.scan_id, Finding.severity)
        ).all():
            sid = str(scan_id)
            key = str(severity or "info").lower()
            n = int(count)
            if sid in sev_by_scan and key in sev_by_scan[sid]:
                sev_by_scan[sid][key] = n
            if sid in total_by_scan:
                total_by_scan[sid] += n
        for scan_id, family, count in db.execute(
            select(Finding.scan_id, Finding.vuln_family, func.count())
            .where(Finding.scan_id.in_(run_ids))
            .group_by(Finding.scan_id, Finding.vuln_family)
        ).all():
            sid = str(scan_id)
            if sid in family_by_scan:
                family_by_scan[sid][str(family or "other")] = int(count)

    runs: list[dict] = []
    for scan, project_name in run_rows:
        summary: dict = {}
        if scan.summary_json:
            try:
                parsed = json.loads(scan.summary_json)
                if isinstance(parsed, dict):
                    summary = parsed
            except json.JSONDecodeError:
                summary = {}
        by_sev = sev_by_scan.get(scan.id) or _empty_severity()
        if not sum(by_sev.values()):
            by_sev = _normalize_severity_counts(summary.get("by_severity"))
        findings_count = total_by_scan.get(scan.id) or 0
        if not findings_count:
            findings_count = int(summary.get("findings_count") or sum(by_sev.values()) or 0)
        by_family = family_by_scan.get(scan.id) or {}
        if not by_family:
            by_family_raw = summary.get("by_family") if isinstance(summary.get("by_family"), dict) else {}
            by_family = {str(k): int(v or 0) for k, v in by_family_raw.items() if v}
        label = (scan.commit_short or (scan.commit_sha or "")[:7] or scan.target or "scan")[:16]
        runs.append(
            {
                "id": scan.id,
                "project_id": scan.project_id,
                "project_name": project_name,
                "label": label,
                "status": scan.status,
                "created_at": scan.finished_at or scan.created_at,
                "findings_count": findings_count,
                "by_severity": by_sev,
                "by_family": by_family,
            }
        )

    open_by_severity = _empty_severity()
    for severity, count in db.execute(
        select(Finding.severity, func.count())
        .select_from(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(owned, Finding.status == "open")
        .group_by(Finding.severity)
    ).all():
        key = str(severity or "info").lower()
        if key in open_by_severity:
            open_by_severity[key] = int(count)

    open_by_severity_by_project: dict[str, dict[str, int]] = {}
    for project_id, severity, count in db.execute(
        select(Scan.project_id, Finding.severity, func.count())
        .select_from(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(owned, Finding.status == "open")
        .group_by(Scan.project_id, Finding.severity)
    ).all():
        pid = str(project_id)
        bucket = open_by_severity_by_project.setdefault(pid, _empty_severity())
        key = str(severity or "info").lower()
        if key in bucket:
            bucket[key] = int(count)

    open_by_family: dict[str, int] = {}
    for family, count in db.execute(
        select(Finding.vuln_family, func.count())
        .select_from(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(owned, Finding.status == "open")
        .group_by(Finding.vuln_family)
        .order_by(func.count().desc())
        .limit(8)
    ).all():
        open_by_family[str(family or "other")] = int(count)

    open_by_engine: dict[str, int] = {}
    for engine, count in db.execute(
        select(Finding.engine, func.count())
        .select_from(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(owned, Finding.status == "open")
        .group_by(Finding.engine)
        .order_by(func.count().desc())
        .limit(8)
    ).all():
        open_by_engine[str(engine or "other")] = int(count)

    outcomes = {"completed": 0, "failed": 0, "cancelled": 0, "running": 0, "queued": 0}
    for status, count in db.execute(
        select(Scan.status, func.count())
        .select_from(Scan)
        .join(Project, Scan.project_id == Project.id)
        .where(owned)
        .group_by(Scan.status)
    ).all():
        key = str(status or "").lower()
        if key in outcomes:
            outcomes[key] = int(count)
        elif key:
            outcomes[key] = int(count)

    return {
        "runs": runs,
        "open_by_severity": open_by_severity,
        "open_by_severity_by_project": open_by_severity_by_project,
        "open_by_family": open_by_family,
        "open_by_engine": open_by_engine,
        "scan_outcomes": outcomes,
    }


def public_project(project: Project) -> dict:
    opts = project_scan_options(project)
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
        "auto_scan_branch": getattr(project, "auto_scan_branch", None)
        or project.github_default_branch,
        "sla_critical_days": getattr(project, "sla_critical_days", 7) or 7,
        "sla_high_days": getattr(project, "sla_high_days", 14) or 14,
        "sla_medium_days": getattr(project, "sla_medium_days", 30) or 30,
        "sla_low_days": getattr(project, "sla_low_days", 90) or 90,
        "require_suppression_approval": bool(getattr(project, "require_suppression_approval", False)),
        "scan_options": opts,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
    }



def project_scan_options(project: Project) -> dict:
    """Saved Advanced defaults for this project (engines, excludes, gates, mode)."""
    default = {
        "engines": list(DEFAULT_ENGINES),
        "path_excludes": ["node_modules/**", "vendor/**", "dist/**"],
        "fail_severity": "off",
        "scan_mode": "rules_only",
        "scan_scope": "full",
        "code_review": False,
    }
    raw = getattr(project, "scan_options_json", None)
    if not raw:
        return default
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return default
    except json.JSONDecodeError:
        return default
    allowed = set(ALL_ENGINES)
    engines = [e for e in (data.get("engines") or default["engines"]) if e in allowed]
    if not engines:
        engines = list(DEFAULT_ENGINES)
    excludes: list[str] = []
    for item in data.get("path_excludes") or default["path_excludes"]:
        cleaned = str(item or "").strip()[:128]
        if cleaned:
            excludes.append(cleaned)
    excludes = excludes[:40]
    fail = (data.get("fail_severity") or "off").strip().lower()
    if fail not in {"off", "critical", "high", "medium"}:
        fail = "off"
    mode = (data.get("scan_mode") or "rules_only").strip().lower()
    if mode not in {"rules_only", "rules_plus_ai"}:
        mode = "rules_only"
    scope = (data.get("scan_scope") or "full").strip().lower()
    if scope not in {"full", "changed"}:
        scope = "full"
    return {
        "engines": engines,
        "path_excludes": excludes,
        "fail_severity": fail,
        "scan_mode": mode,
        "scan_scope": scope,
        "code_review": bool(data.get("code_review")) if "code_review" in data else (mode == "rules_plus_ai"),
    }


def set_project_scan_options(
    project: Project,
    *,
    engines: list[str] | None = None,
    path_excludes: list[str] | None = None,
    fail_severity: str | None = None,
    scan_mode: str | None = None,
    scan_scope: str | None = None,
    code_review: bool | None = None,
) -> dict:
    current = project_scan_options(project)
    allowed = set(ALL_ENGINES)
    if engines is not None:
        chosen = [e for e in engines if e in allowed]
        if not chosen:
            raise HTTPException(status_code=400, detail="Select at least one scan engine.")
        current["engines"] = chosen
    if path_excludes is not None:
        excludes: list[str] = []
        for item in path_excludes:
            cleaned = str(item or "").strip()[:128]
            if cleaned:
                excludes.append(cleaned)
        current["path_excludes"] = excludes[:40]
    if fail_severity is not None:
        fail = fail_severity.strip().lower()
        if fail not in {"off", "critical", "high", "medium"}:
            raise HTTPException(status_code=400, detail="Invalid fail_severity.")
        current["fail_severity"] = fail
    if scan_mode is not None:
        mode = scan_mode.strip().lower()
        if mode not in {"rules_only", "rules_plus_ai"}:
            raise HTTPException(status_code=400, detail="Invalid scan_mode.")
        current["scan_mode"] = mode
        if code_review is None:
            current["code_review"] = mode == "rules_plus_ai"
    if scan_scope is not None:
        scope = scan_scope.strip().lower()
        if scope not in {"full", "changed"}:
            raise HTTPException(status_code=400, detail="Invalid scan_scope.")
        current["scan_scope"] = scope
    if code_review is not None:
        current["code_review"] = bool(code_review)
    project.scan_options_json = json.dumps(current)
    return current



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

    if summary is None and risk is not None:
        summary = {
            "max_risk": risk.get("max_risk"),
            "findings_count": risk.get("open_findings"),
            "by_severity": risk.get("by_severity"),
        }
    elif risk is None and summary is not None:
        risk = {
            "max_risk": summary.get("max_risk"),
            "open_findings": summary.get("findings_count"),
            "by_severity": summary.get("by_severity"),
        }
    elif summary is None and risk is None and scan.status in ("completed", "succeeded", "failed"):
        try:
            from sqlalchemy.orm import object_session
            sess = object_session(scan)
            if sess is not None:
                from app.models.workspace import Finding
                rows = (
                    sess.query(Finding.severity, Finding.risk_score, Finding.effective_priority_score)
                    .filter(Finding.scan_id == scan.id)
                    .all()
                )
                if rows:
                    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                    max_r = 0.0
                    for sev, rs, eps in rows:
                        s = (sev or "info").lower()
                        if s in sev_counts:
                            sev_counts[s] += 1
                        r = max(float(rs or 0.0), float(eps or 0.0))
                        if r > max_r:
                            max_r = r
                    summary = {
                        "findings_count": len(rows),
                        "by_severity": sev_counts,
                        "max_risk": round(max_r, 1),
                    }
                    risk = {
                        "max_risk": round(max_r, 1),
                        "open_findings": len(rows),
                        "by_severity": sev_counts,
                    }
        except Exception:
            pass
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
        "commit_short": (scan.commit_short or (scan.commit_sha or "")[:7] or None)
        and (scan.commit_short or scan.commit_sha or "")[:7],
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
        "options": _scan_options(scan),
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "created_at": scan.created_at,
    }


def _scan_options(scan: Scan) -> dict:
    raw = getattr(scan, "options_json", None)
    if not raw:
        return {
            "engines": list(DEFAULT_ENGINES),
            "path_excludes": [],
            "fail_severity": "off",
            "code_review": False,
        }
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def public_finding(finding: Finding) -> dict:
    countermeasures = None
    if finding.countermeasures_json:
        try:
            countermeasures = json.loads(finding.countermeasures_json)
        except json.JSONDecodeError:
            countermeasures = None

    try:
        matched_engines = json.loads(finding.matched_engines_json or "[]")
        if not isinstance(matched_engines, list) or not matched_engines:
            matched_engines = [finding.engine] if getattr(finding, "engine", None) else ["unknown"]
    except Exception:
        matched_engines = [finding.engine] if getattr(finding, "engine", None) else ["unknown"]

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "engine": finding.engine,
        "rule_id": finding.rule_id,
        "vuln_family": finding.vuln_family,
        "category": getattr(finding, "category", finding.vuln_family),
        "cwe": finding.cwe,
        "owasp_category": finding.owasp_category,
        "owasp": finding.owasp_category,
        "severity": finding.severity,
        "title": finding.title,
        "message": finding.message,
        "description": getattr(finding, "description", finding.message or ""),
        "file_path": public_repo_path(finding.file_path),
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "line_number": getattr(finding, "line_number", finding.line_start or 0),
        "snippet": finding.snippet,
        "code_snippet": getattr(finding, "code_snippet", finding.snippet),
        "risk_score": finding.risk_score,
        "status": finding.status,
        "fingerprint": finding.fingerprint,
        "ai_verdict": finding.ai_verdict,
        "ai_rationale": finding.ai_rationale,
        "countermeasures": countermeasures,
        "countermeasure": getattr(finding, "countermeasure", None),
        "created_at": finding.created_at,
        "is_suppressed": getattr(finding, "is_suppressed", finding.status == "false_positive"),
        # Phase 6A fields
        "cve_id": getattr(finding, "cve_id", None),
        "matched_engines": matched_engines,
        "engine_count": int(getattr(finding, "engine_count", None) or len(matched_engines)),
        "confidence_level": getattr(finding, "confidence_level", "medium"),
        "epss_score": getattr(finding, "epss_score", None),
        "epss_percentile": getattr(finding, "epss_percentile", None),
        "is_kev": bool(getattr(finding, "is_kev", False)),
        "kev_due_date": getattr(finding, "kev_due_date", None),
        "effective_priority_score": float(getattr(finding, "effective_priority_score", 0.0) or 0.0),
        "sla_due_at": ensure_utc(getattr(finding, "sla_due_at", None)),
        "sla_breached": (
            (utcnow() > ensure_utc(finding.sla_due_at))
            if getattr(finding, "sla_due_at", None) and finding.status in ("open", "triage")
            else False
        ),
    }


def get_project_role(db: Session, user: User, project: Project) -> str | None:
    """
    Returns 'owner', 'security_lead', 'developer', 'auditor', or None if the user
    is not a member of project.
    """
    if project.owner_user_id == user.id:
        return "owner"
    member = db.scalar(
        select(ProjectMember).where(
            ProjectMember.project_id == project.id,
            ProjectMember.user_id == user.id,
        )
    )
    return member.role if member else None


def get_project_with_role(
    db: Session,
    user: User,
    project_id: str,
    *,
    allowed_roles: set[str] | None = None,
    require_write: bool = False,
) -> tuple[Project, str]:
    project = db.scalar(select(Project).where(Project.id == project_id))
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")

    role = get_project_role(db, user, project)
    if role is None:
        # Preserve strict 404 isolation for non-members
        raise HTTPException(status_code=404, detail="Project not found.")

    if require_write and role == "auditor":
        raise HTTPException(status_code=403, detail="Auditor role has read-only access.")

    if allowed_roles is not None and role not in allowed_roles:
        raise HTTPException(status_code=403, detail=f"Role '{role}' is not authorized for this action.")

    return project, role


def get_owned_project(
    db: Session,
    user: User,
    project_id: str,
    *,
    require_write: bool = False,
    allowed_roles: set[str] | None = None,
) -> Project:
    project, _ = get_project_with_role(
        db,
        user,
        project_id,
        allowed_roles=allowed_roles,
        require_write=require_write,
    )
    return project


def get_owned_scan(
    db: Session,
    user: User,
    scan_id: str,
    *,
    require_write: bool = False,
    allowed_roles: set[str] | None = None,
) -> tuple[Scan, Project]:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    project = get_owned_project(
        db,
        user,
        scan.project_id,
        require_write=require_write,
        allowed_roles=allowed_roles,
    )
    return scan, project


def expire_stale_suppressions(db: Session, project_id: str) -> int:
    """
    Transitions any FindingSuppression with expires_at < utcnow() to status='expired'
    and re-opens any findings in the project's scans that were suppressed solely by that fingerprint.
    """
    now = utcnow()
    rows = list(
        db.scalars(
            select(FindingSuppression).where(
                FindingSuppression.project_id == project_id,
                FindingSuppression.status == "approved",
                FindingSuppression.expires_at.isnot(None),
            )
        ).all()
    )
    expired_fps: set[str] = set()
    for row in rows:
        exp = ensure_utc(row.expires_at)
        if exp and exp < now:
            row.status = "expired"
            db.add(row)
            if row.fingerprint:
                expired_fps.add(row.fingerprint)

    if expired_fps:
        scan_ids = list(
            db.scalars(select(Scan.id).where(Scan.project_id == project_id)).all()
        )
        if scan_ids:
            findings_to_reopen = list(
                db.scalars(
                    select(Finding).where(
                        Finding.scan_id.in_(scan_ids),
                        Finding.fingerprint.in_(sorted(expired_fps)),
                        Finding.status == "false_positive",
                    )
                ).all()
            )
            for f in findings_to_reopen:
                f.status = "open"
                db.add(f)
        db.commit()

    return len(expired_fps)


def list_projects(db: Session, user: User) -> list[Project]:
    member_proj_ids = list(
        db.scalars(select(ProjectMember.project_id).where(ProjectMember.user_id == user.id)).all()
    )
    if member_proj_ids:
        stmt = (
            select(Project)
            .where((Project.owner_user_id == user.id) | (Project.id.in_(member_proj_ids)))
            .order_by(Project.created_at.desc())
        )
    else:
        stmt = select(Project).where(Project.owner_user_id == user.id).order_by(Project.created_at.desc())
    return list(db.scalars(stmt))



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
    auto_scan_branch: str | None = None,
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
    branch = (auto_scan_branch or "").strip() or project.github_default_branch
    project.auto_scan_branch = branch
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
    auto_scan_branch: str | None = None,
    scan_options: dict | None = None,
    sla_critical_days: int | None = None,
    sla_high_days: int | None = None,
    sla_medium_days: int | None = None,
    sla_low_days: int | None = None,
    require_suppression_approval: bool | None = None,
) -> Project:
    project = get_owned_project(
        db, user, project_id, allowed_roles={"owner", "security_lead"}, require_write=True
    )
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
    if auto_scan_branch is not None:
        project.auto_scan_branch = auto_scan_branch.strip() or None
    if sla_critical_days is not None:
        project.sla_critical_days = max(1, int(sla_critical_days))
    if sla_high_days is not None:
        project.sla_high_days = max(1, int(sla_high_days))
    if sla_medium_days is not None:
        project.sla_medium_days = max(1, int(sla_medium_days))
    if sla_low_days is not None:
        project.sla_low_days = max(1, int(sla_low_days))
    if require_suppression_approval is not None:
        project.require_suppression_approval = bool(require_suppression_approval)
    if scan_options is not None:
        if not isinstance(scan_options, dict):
            raise HTTPException(status_code=400, detail="Invalid scan_options.")
        set_project_scan_options(
            project,
            engines=scan_options.get("engines"),
            path_excludes=scan_options.get("path_excludes"),
            fail_severity=scan_options.get("fail_severity"),
            scan_mode=scan_options.get("scan_mode"),
            scan_scope=scan_options.get("scan_scope"),
            code_review=scan_options.get("code_review"),
        )

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
        project.auto_scan_branch = None
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
        if not project.auto_scan_branch:
            project.auto_scan_branch = project.github_default_branch
        repo_changed = True

    if not project.auto_scan_branch and project.github_default_branch:
        project.auto_scan_branch = project.github_default_branch

    if project.auto_scan_on_push and not project.github_repo_full_name:
        raise HTTPException(status_code=400, detail="Auto-scan on push requires a linked GitHub repository.")

    if auto_scan_on_push is not None or auto_scan_branch is not None or repo_changed:
        sync_project_webhook(db, user, project)

    project.updated_at = utcnow()
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def delete_project(db: Session, user: User, project_id: str) -> None:
    project = get_owned_project(db, user, project_id, allowed_roles={"owner"}, require_write=True)
    if project.github_webhook_id and project.github_repo_full_name:
        try:
            github_svc.delete_repo_webhook(
                db, user, full_name=project.github_repo_full_name, hook_id=int(project.github_webhook_id)
            )
        except Exception:  # noqa: BLE001
            pass
    for row in db.scalars(select(ProjectMember).where(ProjectMember.project_id == project.id)):
        db.delete(row)
    scans = list(db.scalars(select(Scan).where(Scan.project_id == project.id)))
    for scan in scans:
        for finding in db.scalars(select(Finding).where(Finding.scan_id == scan.id)):
            db.delete(finding)
        db.delete(scan)
    for row in db.scalars(select(ScanSbomArtifact).where(ScanSbomArtifact.project_id == project.id)):
        db.delete(row)
    for row in db.scalars(select(FindingSuppression).where(FindingSuppression.project_id == project.id)):
        db.delete(row)
    db.delete(project)
    db.commit()


def list_scans(db: Session, user: User, *, project_id: str | None = None, limit: int = 50) -> list[tuple[Scan, str]]:
    member_proj_ids = list(
        db.scalars(select(ProjectMember.project_id).where(ProjectMember.user_id == user.id)).all()
    )
    if member_proj_ids:
        query = (
            select(Scan, Project.name)
            .join(Project, Scan.project_id == Project.id)
            .where((Project.owner_user_id == user.id) | (Project.id.in_(member_proj_ids)))
        )
    else:
        query = (
            select(Scan, Project.name)
            .join(Project, Scan.project_id == Project.id)
            .where(Project.owner_user_id == user.id)
        )
    if project_id:
        query = query.where(Scan.project_id == project_id)
    rows = db.execute(query.order_by(Scan.created_at.desc()).limit(min(max(limit, 1), 100))).all()
    return [(scan, name) for scan, name in rows]



def list_findings(
    db: Session,
    user: User,
    scan_id: str,
    *,
    is_kev: bool | None = None,
    min_epss: float | None = None,
    min_engines: int | None = None,
    category: str | None = None,
    sort_by: str = "priority",
) -> list[Finding]:
    scan, project = get_owned_scan(db, user, scan_id)
    expire_stale_suppressions(db, project.id)
    query = select(Finding).where(Finding.scan_id == scan_id)


    if is_kev is not None:
        query = query.where(Finding.is_kev.is_(is_kev))
    if min_epss is not None:
        query = query.where(Finding.epss_score.isnot(None), Finding.epss_score >= float(min_epss))
    if min_engines is not None:
        query = query.where(Finding.engine_count >= int(min_engines))
    if category:
        cat = category.strip().lower()
        query = query.where(Finding.vuln_family == cat)

    sev_rank = case(
        (Finding.severity == "critical", 5),
        (Finding.severity == "high", 4),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 2),
        else_=1,
    )

    if sort_by == "severity":
        query = query.order_by(desc(sev_rank), desc(Finding.effective_priority_score), desc(Finding.risk_score))
    elif sort_by == "epss":
        query = query.order_by(
            desc(case((Finding.epss_score.is_(None), -1.0), else_=Finding.epss_score)),
            desc(Finding.effective_priority_score),
            desc(Finding.risk_score),
        )
    else:
        query = query.order_by(
            desc(Finding.effective_priority_score),
            desc(Finding.is_kev),
            desc(Finding.risk_score),
        )

    return list(db.scalars(query))


def get_scan_sbom(db: Session, user: User, project_id: str, scan_id: str) -> ScanSbomArtifact:
    project = get_owned_project(db, user, project_id)
    scan, scan_proj = get_owned_scan(db, user, scan_id)
    if scan_proj.id != project.id:
        raise HTTPException(status_code=404, detail="Scan not found in this project.")
    artifact = db.scalar(
        select(ScanSbomArtifact).where(
            ScanSbomArtifact.scan_id == scan.id,
            ScanSbomArtifact.project_id == project.id,
        )
    )
    if not artifact:
        raise HTTPException(status_code=404, detail="SBOM artifact not found for this scan.")
    return artifact


def public_scan_sbom(artifact: ScanSbomArtifact) -> dict:
    try:
        sbom_dict = json.loads(artifact.sbom_json or "{}")
    except json.JSONDecodeError:
        sbom_dict = {}
    analyzed = analyze_cyclonedx_sbom(sbom_dict)
    try:
        license_summary = json.loads(artifact.license_summary_json or "{}")
    except json.JSONDecodeError:
        license_summary = analyzed.license_summary

    return {
        "id": artifact.id,
        "scan_id": artifact.scan_id,
        "project_id": artifact.project_id,
        "spec_version": artifact.spec_version,
        "component_count": artifact.component_count,
        "policy_violations_count": artifact.policy_violations_count,
        "license_summary": license_summary,
        "components": analyzed.components,
        "created_at": artifact.created_at,
    }


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
    engines: list[str] | None = None,
    path_excludes: list[str] | None = None,
    fail_severity: str | None = None,
    code_review: bool | None = None,
    enforce_quota: bool = True,
) -> Scan:
    project = get_owned_project(db, user, project_id, require_write=True)

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
    saved = project_scan_options(project)
    if scan_mode is not None:
        mode = scan_mode
    else:
        mode = saved.get("scan_mode") or ("rules_plus_ai" if level == "strict" else "rules_only")
    if mode not in {"rules_only", "rules_plus_ai"}:
        raise HTTPException(status_code=400, detail="Invalid scan_mode.")
    if scan_scope is not None:
        scope = (scan_scope or "full").strip().lower()
    else:
        scope = (saved.get("scan_scope") or "full").strip().lower()
    if scope not in {"full", "changed"}:
        raise HTTPException(status_code=400, detail="Invalid scan_scope.")
    if scope == "changed" and resolved_source not in {"github_repo", "github_push"}:
        raise HTTPException(status_code=400, detail="Changed-files scans require a linked GitHub repository.")

    allowed_engines = set(ALL_ENGINES)
    if engines is None:
        chosen = [e for e in saved["engines"] if e in allowed_engines] or list(DEFAULT_ENGINES)
    else:
        chosen = [e for e in engines if e in allowed_engines]
        if not chosen:
            raise HTTPException(
                status_code=400,
                detail="Select at least one scan engine.",
            )
    excludes = []
    exclude_src = path_excludes if path_excludes is not None else saved.get("path_excludes") or []
    for item in exclude_src:
        cleaned = str(item or "").strip()[:128]
        if cleaned:
            excludes.append(cleaned)
    excludes = excludes[:40]

    fail = (fail_severity if fail_severity is not None else saved.get("fail_severity") or "off").strip().lower()
    if fail not in {"off", "critical", "high", "medium"}:
        raise HTTPException(status_code=400, detail="Invalid fail_severity.")

    if code_review is not None:
        review = bool(code_review)
    else:
        review = bool(saved.get("code_review")) if scan_mode is None else (mode == "rules_plus_ai")
    if mode == "rules_plus_ai":
        review = True
    options = {
        "engines": chosen,
        "path_excludes": excludes,
        "fail_severity": fail,
        "code_review": review,
    }

    sha = (commit_sha or "").strip() or None
    short = sha[:7] if sha else None

    eta = estimate_eta_seconds(
        security_level=level,
        scan_mode=mode,
        has_github=bool(project.github_repo_full_name),
        engines=chosen,
    )
    if review:
        eta += 55
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
        options_json=json.dumps(options),
        progress_json=json.dumps(
            {
                "phase": "queued",
                "label": "Getting ready…",
                "percent": 0,
                "eta_remaining_seconds": eta,
                "eta_initial_seconds": eta,
                "logs": [{"t": utcnow().isoformat(), "msg": "Scan queued…"}],
                "findings_so_far": 0,
            }
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


def handle_github_push_event(db: Session, *, payload: dict, project: Project | None = None) -> dict:
    """Create a scan for push to the project's configured auto-scan branch."""
    repo = payload.get("repository") or {}
    repo_id = repo.get("id")
    if repo_id is None:
        return {"ok": True, "skipped": "no_repo"}

    ref = str(payload.get("ref") or "")
    if not ref.startswith("refs/heads/"):
        return {"ok": True, "skipped": "not_branch"}
    branch = ref.removeprefix("refs/heads/")

    if project is None:
        project = db.scalar(
            select(Project).where(
                Project.github_repo_id == int(repo_id),
                Project.auto_scan_on_push.is_(True),
            )
        )
    if not project:
        return {"ok": True, "skipped": "no_project"}

    watch = (
        getattr(project, "auto_scan_branch", None)
        or project.github_default_branch
        or repo.get("default_branch")
        or "main"
    ).strip()
    if branch != watch:
        return {"ok": True, "skipped": "not_watched_branch", "branch": branch, "watched": watch}

    head = payload.get("after") or ((payload.get("head_commit") or {}).get("id"))
    if not head or head == "0000000000000000000000000000000000000000":
        return {"ok": True, "skipped": "no_commit"}

    existing = db.scalar(
        select(Scan).where(
            Scan.project_id == project.id,
            Scan.commit_sha == head,
            Scan.status.notin_(("failed", "cancelled")),
        ).limit(1)
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
    scan, _project = get_owned_scan(db, user, scan_id, require_write=True)
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


def update_finding_status(
    db: Session,
    user: User,
    finding_id: str,
    *,
    status: str,
    suppress: bool = False,
    reason: str | None = None,
    suppression_type: str = "false_positive",
    justification: str | None = None,
    expires_in_days: int | None = None,
    request_approval: bool = False,
) -> Finding:
    status = (status or "").strip().lower()
    if status not in VALID_FINDING_STATUS:
        raise HTTPException(status_code=400, detail="Invalid finding status.")
    finding = db.scalar(select(Finding).where(Finding.id == finding_id))
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    scan, project = get_owned_scan(db, user, finding.scan_id, require_write=True)
    role = get_project_role(db, user, project) or "developer"

    if not finding.fingerprint:
        finding.fingerprint = finding_fingerprint(
            engine=finding.engine,
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            line_start=finding.line_start,
            title=finding.title,
        )

    wants_suppression = suppress or status == "false_positive"
    needs_two_person_review = wants_suppression and (
        role == "developer"
        or request_approval
        or (bool(getattr(project, "require_suppression_approval", False)) and role not in {"owner", "security_lead"})
    )

    expires_at = None
    if expires_in_days is not None and int(expires_in_days) > 0:
        expires_at = utcnow() + timedelta(days=int(expires_in_days))

    if wants_suppression and finding.fingerprint:
        existing = db.scalar(
            select(FindingSuppression).where(
                FindingSuppression.project_id == project.id,
                FindingSuppression.fingerprint == finding.fingerprint,
            )
        )
        effective_reason = (justification or reason or "")[:512] or None
        effective_just = justification or reason or None

        if needs_two_person_review:
            if existing is None:
                supp_row = FindingSuppression(
                    project_id=project.id,
                    fingerprint=finding.fingerprint,
                    reason=effective_reason,
                    created_by_user_id=user.id,
                    status="pending_approval",
                    suppression_type=suppression_type or "risk_accepted",
                    justification=effective_just,
                    requested_by_user_id=user.id,
                    expires_at=expires_at,
                )
                db.add(supp_row)
            else:
                existing.status = "pending_approval"
                existing.suppression_type = suppression_type or existing.suppression_type
                existing.reason = effective_reason
                existing.justification = effective_just
                existing.requested_by_user_id = user.id
                existing.expires_at = expires_at
                db.add(existing)
            # Finding remains open/triage until approved by security_lead or owner
            if finding.status == "false_positive":
                finding.status = "open"
        else:
            now = utcnow()
            if existing is None:
                supp_row = FindingSuppression(
                    project_id=project.id,
                    fingerprint=finding.fingerprint,
                    reason=effective_reason,
                    created_by_user_id=user.id,
                    status="approved",
                    suppression_type=suppression_type or "false_positive",
                    justification=effective_just,
                    requested_by_user_id=user.id,
                    reviewed_by_user_id=user.id,
                    reviewed_at=now,
                    expires_at=expires_at,
                )
                db.add(supp_row)
            else:
                existing.status = "approved"
                existing.suppression_type = suppression_type or existing.suppression_type
                existing.reason = effective_reason
                existing.justification = effective_just
                existing.reviewed_by_user_id = user.id
                existing.reviewed_at = now
                existing.expires_at = expires_at
                db.add(existing)
            finding.status = status
    else:
        finding.status = status

    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def suppress_finding(db: Session, user: User, finding_id: str, *, reason: str | None = None) -> Finding:
    return update_finding_status(
        db,
        user,
        finding_id,
        status="false_positive",
        suppress=True,
        reason=reason,
        justification=reason,
    )



def compare_scans(db: Session, user: User, project_id: str, *, scan_a: str, scan_b: str) -> dict:
    project = get_owned_project(db, user, project_id)
    a, pa = get_owned_scan(db, user, scan_a)
    b, pb = get_owned_scan(db, user, scan_b)
    if pa.id != project.id or pb.id != project.id:
        raise HTTPException(status_code=400, detail="Both scans must belong to this project.")
    comparable = {"completed", "failed"}
    if a.status not in comparable or b.status not in comparable:
        raise HTTPException(
            status_code=400,
            detail="Compare requires two finished scans (completed or policy-failed).",
        )

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
    recent = list_scans(db, user, limit=15)
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
        "charts": _dashboard_charts(db, user),
    }


# ============================================================================
# Phase 6B: Project Member Management & Suppression Review Services
# ============================================================================


def list_project_members(db: Session, user: User, project_id: str) -> list[dict]:
    project = get_owned_project(db, user, project_id)
    owner_user = db.scalar(select(User).where(User.id == project.owner_user_id))
    items: list[dict] = []
    if owner_user:
        items.append(
            {
                "id": f"owner-{owner_user.id}",
                "project_id": project.id,
                "user_id": owner_user.id,
                "email": owner_user.email,
                "username": getattr(owner_user, "username", None),
                "display_name": getattr(owner_user, "display_name", None),
                "role": "owner",
                "added_by_user_id": owner_user.id,
                "created_at": project.created_at,
            }
        )

    members = list(
        db.scalars(
            select(ProjectMember)
            .where(ProjectMember.project_id == project.id)
            .order_by(ProjectMember.created_at.asc())
        ).all()
    )
    for m in members:
        u = db.scalar(select(User).where(User.id == m.user_id))
        if not u or u.id == project.owner_user_id:
            continue
        items.append(
            {
                "id": m.id,
                "project_id": project.id,
                "user_id": u.id,
                "email": u.email,
                "username": getattr(u, "username", None),
                "display_name": getattr(u, "display_name", None),
                "role": m.role,
                "added_by_user_id": m.added_by_user_id,
                "created_at": m.created_at,
            }
        )
    return items


def add_or_update_project_member(
    db: Session,
    actor: User,
    project_id: str,
    *,
    email: str | None = None,
    username: str | None = None,
    user_id: str | None = None,
    role: str,
) -> dict:
    project = get_owned_project(
        db,
        actor,
        project_id,
        allowed_roles={"owner", "security_lead"},
        require_write=True,
    )
    norm_role = (role or "").strip().lower()
    if norm_role not in VALID_MEMBER_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role. Allowed roles: {', '.join(sorted(VALID_MEMBER_ROLES))}",
        )

    target_user: User | None = None
    if user_id:
        target_user = db.scalar(select(User).where(User.id == user_id.strip()))
    elif email:
        target_user = db.scalar(select(User).where(func.lower(User.email) == email.strip().lower()))
    elif username:
        target_user = db.scalar(select(User).where(func.lower(User.username) == username.strip().lower()))

    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found.")
    if target_user.id == project.owner_user_id:
        raise HTTPException(status_code=400, detail="User is already the project owner.")

    existing = db.scalar(
        select(ProjectMember).where(
            ProjectMember.project_id == project.id,
            ProjectMember.user_id == target_user.id,
        )
    )
    if existing is None:
        existing = ProjectMember(
            project_id=project.id,
            user_id=target_user.id,
            role=norm_role,
            added_by_user_id=actor.id,
        )
        db.add(existing)
    else:
        existing.role = norm_role
        existing.added_by_user_id = actor.id
        db.add(existing)

    record_audit_event(
        db,
        action="project.member.added",
        actor_user_id=actor.id,
        target_user_id=target_user.id,
        metadata={"project_id": project.id, "role": norm_role, "member_email": target_user.email},
    )
    db.commit()
    db.refresh(existing)

    return {
        "id": existing.id,
        "project_id": project.id,
        "user_id": target_user.id,
        "email": target_user.email,
        "username": getattr(target_user, "username", None),
        "display_name": getattr(target_user, "display_name", None),
        "role": existing.role,
        "added_by_user_id": existing.added_by_user_id,
        "created_at": existing.created_at,
    }


def remove_project_member(
    db: Session,
    actor: User,
    project_id: str,
    member_user_id: str,
) -> None:
    project = get_owned_project(db, actor, project_id, allowed_roles={"owner"}, require_write=True)
    member = db.scalar(
        select(ProjectMember).where(
            ProjectMember.project_id == project.id,
            ProjectMember.user_id == member_user_id,
        )
    )
    if not member:
        raise HTTPException(status_code=404, detail="Project member not found.")

    db.delete(member)
    record_audit_event(
        db,
        action="project.member.removed",
        actor_user_id=actor.id,
        target_user_id=member_user_id,
        metadata={"project_id": project.id},
    )
    db.commit()


def public_suppression(row: FindingSuppression) -> dict:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "fingerprint": row.fingerprint,
        "reason": row.reason,
        "status": getattr(row, "status", "approved") or "approved",
        "suppression_type": getattr(row, "suppression_type", "false_positive") or "false_positive",
        "justification": getattr(row, "justification", None) or row.reason,
        "created_by_user_id": row.created_by_user_id,
        "requested_by_user_id": getattr(row, "requested_by_user_id", None) or row.created_by_user_id,
        "reviewed_by_user_id": getattr(row, "reviewed_by_user_id", None),
        "reviewed_at": getattr(row, "reviewed_at", None),
        "expires_at": getattr(row, "expires_at", None),
        "created_at": row.created_at,
    }


def list_project_suppressions(db: Session, user: User, project_id: str) -> list[dict]:
    project = get_owned_project(db, user, project_id)
    expire_stale_suppressions(db, project.id)
    rows = list(
        db.scalars(
            select(FindingSuppression)
            .where(FindingSuppression.project_id == project.id)
            .order_by(FindingSuppression.created_at.desc())
        ).all()
    )
    return [public_suppression(r) for r in rows]


def review_finding_suppression(
    db: Session,
    reviewer: User,
    project_id: str,
    suppression_id: str,
    *,
    decision: str,
    review_note: str | None = None,
    expires_in_days: int | None = None,
) -> dict:
    project, role = get_project_with_role(db, reviewer, project_id, require_write=True)
    if role not in {"owner", "security_lead"} and reviewer.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only project owners, security leads, or admins can review suppressions.",
        )

    norm_decision = (decision or "").strip().lower()
    if norm_decision not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="Decision must be 'approved' or 'rejected'.")

    supp = db.scalar(
        select(FindingSuppression).where(
            FindingSuppression.id == suppression_id,
            FindingSuppression.project_id == project.id,
        )
    )
    if not supp:
        raise HTTPException(status_code=404, detail="Suppression record not found.")

    now = utcnow()
    supp.status = norm_decision
    supp.reviewed_by_user_id = reviewer.id
    supp.reviewed_at = now
    if review_note:
        supp.reason = review_note[:512]
    if expires_in_days is not None and int(expires_in_days) > 0:
        supp.expires_at = now + timedelta(days=int(expires_in_days))

    db.add(supp)

    # Apply decision across project scans matching this fingerprint
    scan_ids = list(db.scalars(select(Scan.id).where(Scan.project_id == project.id)).all())
    if scan_ids and supp.fingerprint:
        matching_findings = list(
            db.scalars(
                select(Finding).where(
                    Finding.scan_id.in_(scan_ids),
                    Finding.fingerprint == supp.fingerprint,
                )
            ).all()
        )
        for f in matching_findings:
            if norm_decision == "approved":
                f.status = "false_positive"
            elif norm_decision == "rejected" and f.status == "false_positive":
                f.status = "open"
            db.add(f)

    record_audit_event(
        db,
        action="finding.suppression.reviewed",
        actor_user_id=reviewer.id,
        target_user_id=supp.requested_by_user_id or supp.created_by_user_id,
        metadata={
            "project_id": project.id,
            "suppression_id": supp.id,
            "fingerprint": supp.fingerprint,
            "decision": norm_decision,
        },
    )
    db.commit()
    db.refresh(supp)
    return public_suppression(supp)

































































































































































































































































































