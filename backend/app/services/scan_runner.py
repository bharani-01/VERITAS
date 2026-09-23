from __future__ import annotations

import json
import threading
from collections import Counter
from pathlib import Path
from queue import Empty, Queue

from sqlalchemy import select

from app.core import database as db
from app.core.time import utcnow
from app.models import AppNotification, Finding, FindingSuppression, Project, Scan, User
from app.services.ai_code_review import review_repository
from app.services.ai_report import generate_final_report
from app.services.engines import run_gitleaks, run_osv, run_semgrep
from app.services.engines.normalize import public_repo_path
from app.services.scan_clone import (
    CloneError,
    cleanup_workdir,
    clone_project_repo,
    list_changed_files,
    prepare_workdir,
    purge_all_scan_workdirs,
)

_queue: Queue[str] = Queue()
_worker_started = False
_lock = threading.Lock()


def estimate_eta_seconds(*, security_level: str, scan_mode: str, has_github: bool) -> int:
    base = 90 if has_github else 25
    level = {"basic": 0.75, "standard": 1.15, "strict": 1.75}.get((security_level or "standard").lower(), 1.15)
    ai = 35 if scan_mode == "rules_plus_ai" else 0
    return int(base * level + ai)


PHASE_LABELS = {
    "queued": "Getting ready…",
    "cloning": "Pulling your repository…",
    "secrets": "Looking for exposed secrets…",
    "sca": "Checking dependencies…",
    "semgrep": "Reading through the code…",
    "code_review": "AI code review…",
    "reporting": "Writing the security report…",
    "completed": "Done",
    "failed": "Something went wrong",
    "cancelled": "Cancelled",
}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _parse_options(scan: Scan) -> dict:
    raw = getattr(scan, "options_json", None)
    default = {
        "engines": ["gitleaks", "osv", "semgrep"],
        "path_excludes": [],
        "fail_severity": "off",
        "code_review": False,
    }
    if not raw:
        return default
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return default
        engines = [e for e in (data.get("engines") or default["engines"]) if e in {"gitleaks", "osv", "semgrep"}]
        if not engines:
            engines = default["engines"]
        return {
            "engines": engines,
            "path_excludes": list(data.get("path_excludes") or [])[:40],
            "fail_severity": (data.get("fail_severity") or "off"),
            "code_review": bool(data.get("code_review")),
        }
    except json.JSONDecodeError:
        return default


def _countermeasures_for(nf, family: str, severity: str) -> list[dict]:
    steps = None
    if isinstance(nf.raw, dict):
        raw_steps = nf.raw.get("ai_fix_steps")
        if isinstance(raw_steps, list) and raw_steps:
            steps = [str(s) for s in raw_steps]
    if steps:
        return [{"title": "AI recommended fix", "steps": steps, "severity": severity}]
    return _playbook_for(family, severity)


class ScanCancelled(Exception):
    pass


def _set_progress(session, scan: Scan, *, phase: str, percent: int, eta_remaining: int | None = None) -> None:
    scan.progress_json = json.dumps(
        {
            "phase": phase,
            "label": PHASE_LABELS.get(phase, "Working…"),
            "percent": percent,
            "eta_remaining_seconds": eta_remaining,
        }
    )
    if eta_remaining is not None:
        scan.eta_seconds = eta_remaining
    session.add(scan)
    session.commit()


def _check_cancel(session, scan: Scan) -> None:
    session.refresh(scan)
    if scan.cancel_requested:
        raise ScanCancelled()


def _playbook_for(family: str, severity: str) -> list[dict]:
    tips = {
        "sqli": ["Use parameterized queries / ORM bind parameters.", "Never concatenate user input into SQL."],
        "xss": ["Encode output for HTML context.", "Prefer framework auto-escaping; sanitize rich text carefully."],
        "csrf": ["Require anti-CSRF tokens on state-changing requests.", "Set SameSite=Lax/Strict on session cookies."],
        "secret": ["Rotate the exposed credential immediately.", "Remove secrets from git history; use a secret manager."],
        "sca": ["Upgrade the vulnerable dependency.", "Review advisories and apply patches or replacements."],
        "other": ["Review the rule guidance and apply the least-privilege secure alternative."],
    }
    return [{"title": "Recommended countermeasure", "steps": tips.get(family, tips["other"]), "severity": severity}]


def _notify(session, scan: Scan, project: Project, user: User, summary: dict) -> None:
    count = int(summary.get("findings_count") or 0)
    status_label = (scan.status or "unknown").replace("_", " ")
    title = f"Scan finished · {project.name}"
    body = f"{status_label} · {count} finding{'s' if count != 1 else ''}"
    if scan.notify_in_app:
        session.add(
            AppNotification(
                user_id=user.id,
                scan_id=scan.id,
                title=title,
                body=body,
            )
        )
        session.commit()
    if scan.notify_email and user.email:
        try:
            from app.services.email import send_scan_finished

            send_scan_finished(
                session,
                user,
                project_name=project.name,
                project_id=project.id,
                scan_id=scan.id,
                status=scan.status,
                findings_count=count,
                scan_mode=scan.scan_mode or "rules_only",
            )
            session.commit()
        except Exception:
            session.rollback()


def run_scan_job(scan_id: str) -> None:
    workdir: Path | None = None
    try:
        with db.SessionLocal() as session:
            scan = session.get(Scan, scan_id)
            if not scan:
                return
            project = session.get(Project, scan.project_id)
            user = session.get(User, scan.created_by_user_id)
            if not project or not user:
                scan.status = "failed"
                scan.error_message = "Missing project or user."
                scan.finished_at = utcnow()
                session.add(scan)
                session.commit()
                return

            if scan.cancel_requested:
                scan.status = "cancelled"
                scan.finished_at = utcnow()
                scan.progress_json = json.dumps(
                    {"phase": "cancelled", "label": PHASE_LABELS["cancelled"], "percent": 100, "eta_remaining_seconds": 0}
                )
                session.add(scan)
                session.commit()
                return

            scan.status = "running"
            scan.started_at = utcnow()
            scan.error_message = None
            session.add(scan)
            session.commit()

            engine_meta: list[dict] = []
            findings_out: list = []
            try:
                _set_progress(session, scan, phase="cloning", percent=5, eta_remaining=scan.eta_seconds)
                _check_cancel(session, scan)
                workdir = prepare_workdir(scan.id)
                repo_path: Path | None = None
                changed_paths: list[str] | None = None
                if scan.source == "github_repo" and project.github_repo_full_name:
                    repo_dir, git_meta = clone_project_repo(session, user, project, workdir, ref=scan.ref)
                    repo_path = Path(repo_dir)
                    scan.commit_sha = git_meta.get("commit_sha")
                    scan.commit_short = git_meta.get("commit_short")
                    scan.commit_message = git_meta.get("commit_message")
                    scan.commit_author = git_meta.get("commit_author")
                    scan.git_history_json = json.dumps(git_meta.get("history") or [])
                    session.add(scan)
                    session.commit()
                    if (scan.scan_scope or "full") == "changed":
                        base = project.github_default_branch or "main"
                        changed_paths = list_changed_files(repo_path, base_branch=base)
                        engine_meta.append({"engine": "diff", "changed_files": len(changed_paths), "base": base})
                else:
                    engine_meta.append({"engine": "clone", "skipped": "manual target — no GitHub clone"})
                    repo_path = None

                _check_cancel(session, scan)
                options = _parse_options(scan)
                enabled = set(options["engines"])
                excludes = options["path_excludes"]
                want_review = bool(options["code_review"]) or scan.scan_mode == "rules_plus_ai"

                if repo_path:
                    if "gitleaks" in enabled:
                        _set_progress(
                            session, scan, phase="secrets", percent=20, eta_remaining=max(10, (scan.eta_seconds or 60) // 2)
                        )
                        g_findings, g_meta = run_gitleaks(repo_path)
                        engine_meta.append(g_meta)
                        findings_out.extend(g_findings)
                    else:
                        engine_meta.append({"engine": "gitleaks", "skipped": "disabled"})

                    _check_cancel(session, scan)
                    if "osv" in enabled:
                        _set_progress(
                            session, scan, phase="sca", percent=40, eta_remaining=max(8, (scan.eta_seconds or 60) // 3)
                        )
                        o_findings, o_meta = run_osv(repo_path)
                        engine_meta.append(o_meta)
                        findings_out.extend(o_findings)
                    else:
                        engine_meta.append({"engine": "osv", "skipped": "disabled"})

                    _check_cancel(session, scan)
                    if "semgrep" in enabled:
                        _set_progress(
                            session, scan, phase="semgrep", percent=60, eta_remaining=max(5, (scan.eta_seconds or 60) // 4)
                        )
                        s_findings, s_meta = run_semgrep(
                            repo_path,
                            security_level=scan.security_level,
                            include_paths=changed_paths,
                            excludes=excludes,
                        )
                        engine_meta.append(s_meta)
                        findings_out.extend(s_findings)
                    else:
                        engine_meta.append({"engine": "semgrep", "skipped": "disabled"})

                    if want_review:
                        _check_cancel(session, scan)
                        _set_progress(
                            session, scan, phase="code_review", percent=78, eta_remaining=max(4, (scan.eta_seconds or 40) // 5)
                        )
                        r_findings, r_meta = review_repository(
                            repo_path,
                            include_paths=changed_paths,
                            excludes=excludes,
                        )
                        engine_meta.append(r_meta)
                        findings_out.extend(r_findings)
                    else:
                        engine_meta.append({"engine": "openrouter_review", "skipped": "disabled"})

                    root = str(repo_path)
                    for nf in findings_out:
                        nf.file_path = public_repo_path(nf.file_path, repo_root=root)
                else:
                    for name in ("gitleaks", "osv", "semgrep", "openrouter_review"):
                        engine_meta.append({"engine": name, "skipped": "no repository workspace"})

                cleanup_workdir(workdir)
                workdir = None

                suppressed = {
                    row.fingerprint
                    for row in session.scalars(
                        select(FindingSuppression).where(FindingSuppression.project_id == project.id)
                    ).all()
                }

                ai_status = "skipped"
                ai_report = None
                if scan.scan_mode == "rules_plus_ai" or want_review:
                    _check_cancel(session, scan)
                    _set_progress(session, scan, phase="reporting", percent=90, eta_remaining=5)
                    report_meta = generate_final_report(
                        findings_out,
                        project_name=project.name,
                        target=scan.target,
                    )
                    ai_status = report_meta.get("status") or "ok"
                    ai_report = report_meta.get("report_markdown")
                    engine_meta.append(
                        {
                            "engine": "groq_report",
                            "status": ai_status,
                            "model": report_meta.get("model"),
                            "findings_in_report": report_meta.get("findings_in_report"),
                        }
                    )

                _check_cancel(session, scan)
                _set_progress(session, scan, phase="reporting", percent=95, eta_remaining=2)
                for old in session.scalars(select(Finding).where(Finding.scan_id == scan.id)):
                    session.delete(old)
                session.commit()

                severity_counts: Counter[str] = Counter()
                family_counts: Counter[str] = Counter()
                suppressed_count = 0
                for nf in findings_out:
                    fp = nf.fingerprint()
                    status = "false_positive" if fp in suppressed else "open"
                    if status == "false_positive":
                        suppressed_count += 1
                    severity_counts[nf.severity] += 1
                    family_counts[nf.vuln_family] += 1
                    ai_verdict = None
                    ai_rationale = None
                    if isinstance(nf.raw, dict):
                        ai_verdict = nf.raw.get("ai_verdict")
                        ai_rationale = nf.raw.get("ai_rationale")
                    session.add(
                        Finding(
                            scan_id=scan.id,
                            engine=nf.engine,
                            rule_id=nf.rule_id,
                            vuln_family=nf.vuln_family,
                            cwe=nf.cwe,
                            owasp_category=nf.owasp_category,
                            severity=nf.severity,
                            title=nf.title[:512],
                            message=nf.message,
                            file_path=nf.file_path,
                            line_start=nf.line_start,
                            line_end=nf.line_end,
                            snippet=nf.snippet,
                            risk_score=nf.risk_score(criticality=project.criticality),
                            status=status,
                            fingerprint=fp,
                            ai_verdict=ai_verdict,
                            ai_rationale=ai_rationale,
                            countermeasures_json=json.dumps(
                                _countermeasures_for(nf, nf.vuln_family, nf.severity)
                            ),
                            raw_json=json.dumps(nf.raw)[:20000] if nf.raw else None,
                        )
                    )

                open_findings = [nf for nf in findings_out if nf.fingerprint() not in suppressed]
                open_count = len(open_findings)
                max_risk = max(
                    (nf.risk_score(criticality=project.criticality) for nf in open_findings),
                    default=0.0,
                )

                fail_at = (options.get("fail_severity") or "off").lower()
                policy_failed = False
                if fail_at != "off":
                    threshold = _SEVERITY_RANK.get(fail_at, 99)
                    for nf in open_findings:
                        if _SEVERITY_RANK.get((nf.severity or "").lower(), 0) >= threshold:
                            policy_failed = True
                            break

                summary = {
                    "findings_count": len(findings_out),
                    "open_count": open_count,
                    "suppressed_count": suppressed_count,
                    "by_severity": dict(severity_counts),
                    "by_family": dict(family_counts),
                    "engines": engine_meta,
                    "scan_mode": scan.scan_mode,
                    "scan_scope": scan.scan_scope or "full",
                    "security_level": scan.security_level,
                    "options": options,
                    "ai_status": ai_status,
                    "ai_report": ai_report,
                    "max_risk": max_risk,
                    "commit_short": scan.commit_short,
                    "commit_sha": scan.commit_sha,
                    "workspace_purged": True,
                    "policy_failed": policy_failed,
                    "fail_severity": fail_at,
                }
                scan.summary_json = json.dumps(summary)
                scan.risk_summary_json = json.dumps(
                    {"max_risk": max_risk, "open_findings": open_count, "by_severity": dict(severity_counts)}
                )
                if policy_failed:
                    scan.status = "failed"
                    scan.error_message = (
                        f"Severity policy failed: open finding at or above '{fail_at}'."
                    )[:1000]
                else:
                    scan.status = "completed"
                    scan.error_message = None
                scan.finished_at = utcnow()
                scan.progress_json = json.dumps(
                    {
                        "phase": "completed" if not policy_failed else "failed",
                        "label": PHASE_LABELS["failed" if policy_failed else "completed"],
                        "percent": 100,
                        "eta_remaining_seconds": 0,
                    }
                )
                scan.eta_seconds = 0
                session.add(scan)
                session.commit()
                _notify(session, scan, project, user, summary)
            except ScanCancelled:
                scan.status = "cancelled"
                scan.error_message = "Scan cancelled by user."
                scan.finished_at = utcnow()
                scan.progress_json = json.dumps(
                    {"phase": "cancelled", "label": PHASE_LABELS["cancelled"], "percent": 100, "eta_remaining_seconds": 0}
                )
                scan.eta_seconds = 0
                session.add(scan)
                session.commit()
                _notify(session, scan, project, user, {"findings_count": 0})
            except CloneError as exc:
                scan.status = "failed"
                scan.error_message = str(exc)[:1000]
                scan.finished_at = utcnow()
                scan.progress_json = json.dumps(
                    {"phase": "failed", "label": PHASE_LABELS["failed"], "percent": 100, "eta_remaining_seconds": 0}
                )
                session.add(scan)
                session.commit()
                _notify(session, scan, project, user, {"findings_count": 0})
            except Exception as exc:
                scan.status = "failed"
                scan.error_message = str(exc)[:1000]
                scan.finished_at = utcnow()
                scan.progress_json = json.dumps(
                    {"phase": "failed", "label": PHASE_LABELS["failed"], "percent": 100, "eta_remaining_seconds": 0}
                )
                session.add(scan)
                session.commit()
                _notify(session, scan, project, user, {"findings_count": 0})
    finally:
        cleanup_workdir(workdir)


def _worker_loop() -> None:
    while True:
        try:
            scan_id = _queue.get(timeout=1.0)
        except Empty:
            continue
        try:
            run_scan_job(scan_id)
        except Exception:
            pass
        finally:
            _queue.task_done()


def _recover_orphaned_scans() -> None:
    try:
        purge_all_scan_workdirs()
        with db.SessionLocal() as session:
            rows = session.scalars(
                select(Scan).where(Scan.status.in_(("queued", "running"))).order_by(Scan.created_at.asc())
            ).all()
            for scan in rows:
                if scan.cancel_requested:
                    scan.status = "cancelled"
                    scan.finished_at = utcnow()
                    scan.progress_json = json.dumps(
                        {
                            "phase": "cancelled",
                            "label": PHASE_LABELS["cancelled"],
                            "percent": 100,
                            "eta_remaining_seconds": 0,
                        }
                    )
                    session.add(scan)
                    continue
                scan.status = "queued"
                scan.error_message = None
                scan.finished_at = None
                scan.progress_json = json.dumps(
                    {
                        "phase": "queued",
                        "label": PHASE_LABELS["queued"],
                        "percent": 0,
                        "eta_remaining_seconds": scan.eta_seconds,
                    }
                )
                session.add(scan)
            session.commit()
            for scan in rows:
                if scan.status == "queued":
                    _queue.put(scan.id)
    except Exception:
        pass


def ensure_scan_worker() -> None:
    global _worker_started
    with _lock:
        if _worker_started:
            return
        thread = threading.Thread(target=_worker_loop, name="veritas-scan-worker", daemon=True)
        thread.start()
        _worker_started = True
        _recover_orphaned_scans()


def enqueue_scan(scan_id: str) -> None:
    ensure_scan_worker()
    _queue.put(scan_id)
