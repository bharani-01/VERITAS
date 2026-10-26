from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import PUBLIC_APP_URL
from app.core.database import db_session
from app.models import User
from app.schemas.workspace import (
    FindingStatusPatch,
    FindingStatusUpdate,
    FindingSuppressCreate,
    ProjectCreate,
    ProjectMemberIn,
    ProjectUpdate,
    ScanCreate,
    SuppressionReviewIn,
)
from app.services import github as github_svc
from app.services import projects as project_svc
from app.services.audit import audit
from app.services.compliance import evaluate_scan_compliance, render_compliance_certificate_html

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
            sla_critical_days=body.sla_critical_days,
            sla_high_days=body.sla_high_days,
            sla_medium_days=body.sla_medium_days,
            sla_low_days=body.sla_low_days,
            require_suppression_approval=body.require_suppression_approval,
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
    is_kev: bool | None = Query(default=None),
    min_epss: float | None = Query(default=None, ge=0.0, le=1.0),
    min_engines: int | None = Query(default=None, ge=1),
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    sort_by: str = Query(default="priority", pattern="^(priority|severity|epss)$"),
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
    project_id: str | None = None,
):
    from sqlalchemy import case, desc
    from app.models.workspace import Finding, Scan

    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    resolved_proj_id = project_id or scan.project_id
    project_svc.get_owned_project(db, user, resolved_proj_id)

    query = db.query(Finding).filter(Finding.scan_id == scan_id)

    if is_kev is not None:
        query = query.filter(Finding.is_kev.is_(is_kev))
    if min_epss is not None:
        query = query.filter(Finding.epss_score.isnot(None), Finding.epss_score >= min_epss)
    if min_engines is not None:
        query = query.filter(Finding.engine_count >= min_engines)
    if category:
        c_clean = category.strip().lower()
        query = query.filter((Finding.vuln_family == c_clean) | (Finding.engine == c_clean))
    if severity:
        query = query.filter(Finding.severity == severity.strip().lower())
    if status_filter:
        query = query.filter(Finding.status == status_filter.strip().lower())

    severity_rank_expr = case(
        (Finding.severity == "critical", 5),
        (Finding.severity == "high", 4),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 2),
        else_=1,
    )

    if sort_by == "severity":
        query = query.order_by(
            desc(severity_rank_expr),
            desc(Finding.effective_priority_score),
            Finding.id.asc(),
        )
    elif sort_by == "epss":
        query = query.order_by(
            desc(case((Finding.epss_score.is_(None), -1.0), else_=Finding.epss_score)),
            desc(Finding.effective_priority_score),
            Finding.id.asc(),
        )
    else:
        # Default: sort_by == "priority"
        query = query.order_by(
            desc(Finding.effective_priority_score),
            desc(Finding.is_kev),
            desc(severity_rank_expr),
            Finding.id.asc(),
        )

    rows = query.all()
    serialized = [project_svc.public_finding(f) for f in rows]

    return {
        "scan_id": scan.id,
        "project_id": resolved_proj_id,
        "raw_findings_count": getattr(scan, "raw_findings_count", len(serialized)) or len(serialized),
        "correlated_findings_count": getattr(scan, "correlated_findings_count", len(serialized)) or len(serialized),
        "total": len(serialized),
        "findings": serialized,
        "items": serialized,
    }


@router.get("/projects/{project_id}/scans/{scan_id}/sbom")
def get_scan_sbom_summary(
    project_id: str,
    scan_id: str,
    db: Session = Depends(db_session),
    user: User = Depends(get_current_user),
):
    import json
    from app.models.workspace import Scan, ScanSbomArtifact
    from app.services.engines.trivy_sbom import analyze_cyclonedx_sbom

    project = project_svc.get_owned_project(db, user, project_id)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.project_id == project.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    artifact = (
        db.query(ScanSbomArtifact)
        .filter(ScanSbomArtifact.scan_id == scan.id, ScanSbomArtifact.project_id == project.id)
        .first()
    )
    if not artifact:
        raise HTTPException(
            status_code=404,
            detail="SBOM artifact not found for this scan",
        )

    try:
        sbom_dict = json.loads(artifact.sbom_json or "{}")
    except Exception:
        sbom_dict = {}

    analyzed = analyze_cyclonedx_sbom(sbom_dict)
    try:
        license_summary = json.loads(artifact.license_summary_json or "{}")
    except Exception:
        license_summary = analyzed.license_summary

    return {
        "scan_id": scan.id,
        "project_id": project_id,
        "spec_version": artifact.spec_version,
        "component_count": artifact.component_count,
        "policy_violations_count": artifact.policy_violations_count,
        "license_summary": license_summary,
        "components": analyzed.components,
        "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
    }


@router.get("/projects/{project_id}/scans/{scan_id}/sbom/download")
def download_scan_sbom_cyclonedx(
    project_id: str,
    scan_id: str,
    db: Session = Depends(db_session),
    user: User = Depends(get_current_user),
):
    from fastapi import Response
    from app.models.workspace import Scan, ScanSbomArtifact

    project = project_svc.get_owned_project(db, user, project_id)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.project_id == project.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    artifact = (
        db.query(ScanSbomArtifact)
        .filter(ScanSbomArtifact.scan_id == scan.id, ScanSbomArtifact.project_id == project.id)
        .first()
    )
    if not artifact:
        raise HTTPException(
            status_code=404,
            detail="SBOM artifact not found for this scan",
        )

    filename = f"veritas-sbom-scan-{scan.id}.cdx.json"
    return Response(
        content=artifact.sbom_json,
        media_type="application/vnd.cyclonedx+json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.patch("/findings/{finding_id}")
def patch_finding(
    finding_id: str,
    payload: FindingStatusPatch,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    finding = project_svc.update_finding_status(
        db,
        user,
        finding_id,
        status=payload.status,
        suppress=payload.suppress,
        reason=payload.reason,
        suppression_type=payload.suppression_type,
        justification=payload.justification,
        expires_in_days=payload.expires_in_days,
        request_approval=payload.request_approval,
    )
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


# ============================================================================
# Phase 6B: Project Member RBAC Endpoints
# ============================================================================


@router.get("/projects/{project_id}/members")
def list_members(
    project_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    items = project_svc.list_project_members(db, user, project_id)
    return {"items": items, "members": items, "total": len(items)}


@router.post("/projects/{project_id}/members")
def add_member(
    project_id: str,
    payload: ProjectMemberIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    member = project_svc.add_or_update_project_member(
        db,
        user,
        project_id,
        email=payload.email,
        username=payload.username,
        user_id=payload.user_id,
        role=payload.role,
    )
    return {"member": member}


@router.delete("/projects/{project_id}/members/{member_user_id}")
def remove_member(
    project_id: str,
    member_user_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    project_svc.remove_project_member(db, user, project_id, member_user_id)
    return {"removed": True, "user_id": member_user_id}


# ============================================================================
# Phase 6B: Suppression Governance Endpoints
# ============================================================================


@router.get("/projects/{project_id}/suppressions")
def get_project_suppressions(
    project_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    items = project_svc.list_project_suppressions(db, user, project_id)
    return {"items": items, "suppressions": items, "total": len(items)}


@router.post("/projects/{project_id}/suppressions/{suppression_id}/review")
def review_suppression(
    project_id: str,
    suppression_id: str,
    payload: SuppressionReviewIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    reviewed = project_svc.review_finding_suppression(
        db,
        user,
        project_id,
        suppression_id,
        decision=payload.decision,
        review_note=payload.review_note,
        expires_in_days=payload.expires_in_days,
    )
    return {"suppression": reviewed}


# ============================================================================
# Phase 6B: Compliance Posture & Certificate Export Endpoints
# ============================================================================


@router.get("/projects/{project_id}/scans/{scan_id}/compliance")
def get_scan_compliance_posture(
    project_id: str,
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    project = project_svc.get_owned_project(db, user, project_id)
    scan, scan_proj = project_svc.get_owned_scan(db, user, scan_id)
    if scan_proj.id != project.id:
        raise HTTPException(status_code=404, detail="Scan not found in this project.")
    project_svc.expire_stale_suppressions(db, project.id)
    return evaluate_scan_compliance(db, project, scan)


@router.get("/projects/{project_id}/scans/{scan_id}/compliance/export")
def export_scan_compliance_certificate(
    project_id: str,
    scan_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    project = project_svc.get_owned_project(db, user, project_id)
    scan, scan_proj = project_svc.get_owned_scan(db, user, scan_id)
    if scan_proj.id != project.id:
        raise HTTPException(status_code=404, detail="Scan not found in this project.")
    project_svc.expire_stale_suppressions(db, project.id)
    compliance_data = evaluate_scan_compliance(db, project, scan)
    html_doc = render_compliance_certificate_html(compliance_data)
    filename = f"veritas-compliance-certificate-{scan.id}.html"
    return HTMLResponse(
        content=html_doc,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


from app.services.remediation import generate_finding_fix_plan


@router.post("/findings/{finding_id}/fix-plan")
def create_finding_fix_plan(
    finding_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(db_session),
):
    return generate_finding_fix_plan(db, user, finding_id)


