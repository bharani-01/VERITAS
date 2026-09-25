from __future__ import annotations

import json
import threading
from collections import Counter
from pathlib import Path
from queue import Empty, Queue

from sqlalchemy import select

from app.core import database as db
from app.core.time import ensure_utc, utcnow
from app.models import AppNotification, Finding, FindingSuppression, Project, Scan, User
from app.services.ai_code_review import review_repository
from app.services.ai_report import generate_final_report
from app.services.engines import (
    ALL_ENGINES,
    DEFAULT_ENGINES,
    run_bandit,
    run_checkov,
    run_detect_secrets,
    run_gitleaks,
    run_hadolint,
    run_njsscan,
    run_osv,
    run_pip_audit,
    run_semgrep,
    run_shellcheck,
    run_trivy,
    run_trufflehog,
)
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


def estimate_eta_seconds(
    *,
    security_level: str,
    scan_mode: str,
    has_github: bool,
    engines: list[str] | None = None,
) -> int:
    """Initial wall-clock guess (seconds). Conservative — real ETA is refined from progress."""
    allowed = set(ALL_ENGINES)
    chosen = [e for e in (engines or list(DEFAULT_ENGINES)) if e in allowed]
    if not chosen:
        chosen = list(DEFAULT_ENGINES)
    total = 25 if has_github else 8  # clone / setup
    costs = {
        "gitleaks": 50,
        "osv": 45,
        "semgrep": 150,
        "trufflehog": 90,
        "trivy": 120,
        "bandit": 60,
        "detect_secrets": 55,
        "pip_audit": 40,
        "checkov": 100,
        "njsscan": 70,
        "hadolint": 25,
        "shellcheck": 30,
    }
    for engine in chosen:
        total += costs.get(engine, 60)
    level = {"basic": 0.7, "standard": 1.0, "strict": 1.4}.get((security_level or "standard").lower(), 1.0)
    ai = 55 if (scan_mode or "") == "rules_plus_ai" else 0
    return max(30, int(total * level + ai))


def _initial_eta(scan: Scan) -> int:
    prev = _read_progress(scan)
    raw = prev.get("eta_initial_seconds")
    try:
        if raw is not None:
            return max(30, int(raw))
    except (TypeError, ValueError):
        pass
    try:
        return max(30, int(scan.eta_seconds or 180))
    except (TypeError, ValueError):
        return 180


def _remaining_eta(scan: Scan, percent: int) -> int:
    """
    Live ETA from elapsed wall time + percent complete.
    Avoids the old bug of repeatedly dividing a shrinking eta_seconds into ~5–9s.
    """
    pct = max(1, min(99, int(percent or 1)))
    initial = _initial_eta(scan)
    if not scan.started_at:
        return initial
    try:
        elapsed = max(1, int((utcnow() - ensure_utc(scan.started_at)).total_seconds()))
    except Exception:
        return max(15, initial // 2)

    if pct <= 8:
        return max(20, initial - elapsed)

    extrapolated_total = int(elapsed * 100 / pct)
    if pct < 30:
        blended = int(0.5 * extrapolated_total + 0.5 * max(initial, elapsed + 30))
    elif pct < 70:
        blended = int(0.75 * extrapolated_total + 0.25 * max(initial, elapsed + 20))
    else:
        blended = max(extrapolated_total, elapsed + 10)
    remaining = blended - elapsed
    # Cap so a stuck early percent cannot claim hours forever
    return max(8, min(remaining, 60 * 45))


PHASE_LABELS = {
    "queued": "Getting ready…",
    "cloning": "Pulling your repository…",
    "secrets": "Looking for exposed secrets…",
    "secrets_deep": "Deep secret hunt…",
    "secrets_entropy": "Entropy secret scan…",
    "sca": "Checking dependencies…",
    "sca_python": "Auditing Python packages…",
    "sca_deep": "Deep dependency & config check…",
    "iac": "Checking infrastructure as code…",
    "semgrep": "Reading through the code…",
    "bandit": "Python security pass…",
    "nodejs": "Node.js security pass…",
    "docker": "Dockerfile review…",
    "shell": "Shell script review…",
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
        "engines": list(DEFAULT_ENGINES),
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
        allowed = set(ALL_ENGINES)
        engines = [e for e in (data.get("engines") or default["engines"]) if e in allowed]
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


def _read_progress(scan: Scan) -> dict:
    if not scan.progress_json:
        return {}
    try:
        data = json.loads(scan.progress_json)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _set_progress(
    session,
    scan: Scan,
    *,
    phase: str,
    percent: int,
    eta_remaining: int | None = None,
    log: str | None = None,
    clear_logs: bool = False,
) -> None:
    prev = _read_progress(scan)
    logs = [] if clear_logs else list(prev.get("logs") or [])
    if log:
        logs.append({"t": utcnow().isoformat(), "msg": log[:240]})
    # Cap so progress_json stays small
    logs = logs[-100:]
    pct = max(0, min(100, int(percent)))
    initial = prev.get("eta_initial_seconds")
    if initial is None:
        try:
            initial = int(scan.eta_seconds or 180)
        except (TypeError, ValueError):
            initial = 180
    if eta_remaining is None and pct < 100:
        eta_remaining = _remaining_eta(scan, pct)
    if pct >= 100:
        eta_remaining = 0
    scan.progress_json = json.dumps(
        {
            "phase": phase,
            "label": PHASE_LABELS.get(phase, "Working…"),
            "percent": pct,
            "eta_remaining_seconds": eta_remaining,
            "eta_initial_seconds": int(initial),
            "logs": logs,
            "findings_so_far": int(prev.get("findings_so_far") or 0),
        }
    )
    if eta_remaining is not None:
        scan.eta_seconds = eta_remaining
    session.add(scan)
    session.commit()


def _bump_findings_so_far(session, scan: Scan, count: int) -> None:
    prev = _read_progress(scan)
    total = int(prev.get("findings_so_far") or 0) + max(0, count)
    prev["findings_so_far"] = total
    prev["logs"] = list(prev.get("logs") or [])
    if "eta_initial_seconds" not in prev:
        prev["eta_initial_seconds"] = _initial_eta(scan)
    scan.progress_json = json.dumps(prev)
    session.add(scan)
    session.commit()


def _log_engine_results(
    session,
    scan: Scan,
    *,
    phase: str,
    percent: int,
    eta_remaining: int | None = None,
    started_msg: str,
    empty_msg: str,
    found_msg: str,
    findings: list,
) -> None:
    _set_progress(session, scan, phase=phase, percent=percent, eta_remaining=eta_remaining, log=started_msg)
    n = len(findings)
    if n == 0:
        _set_progress(session, scan, phase=phase, percent=percent, eta_remaining=eta_remaining, log=empty_msg)
        return
    _set_progress(
        session,
        scan,
        phase=phase,
        percent=percent,
        eta_remaining=eta_remaining,
        log=found_msg.format(n=n),
    )
    _bump_findings_so_far(session, scan, n)
    for nf in findings[:8]:
        loc = ""
        if getattr(nf, "file_path", None):
            loc = f" · {nf.file_path}"
            if getattr(nf, "line_start", None):
                loc += f":{nf.line_start}"
        sev = (getattr(nf, "severity", None) or "info").lower()
        title = (getattr(nf, "title", None) or "Issue")[:120]
        _set_progress(
            session,
            scan,
            phase=phase,
            percent=percent,
            eta_remaining=eta_remaining,
            log=f"[{sev}] {title}{loc}",
        )


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


_EXPECTED_SKIP_MARKERS = (
    "disabled",
    "no requirements",
    "no dockerfile",
    "no shell",
    "no changed",
    "no repository",
    "manual target",
    "cancelled",
)

_MISSING_MARKERS = ("not found", "binary not found")


def _collect_ops_issues(
    engine_meta: list[dict] | None,
    *,
    scan_status: str | None = None,
    error_message: str | None = None,
) -> list[str]:
    """Build human-readable ops issues (missing tools / engine errors / scan failure)."""
    issues: list[str] = []
    status = (scan_status or "").lower()
    err_msg = (error_message or "").strip()
    # User severity gates are intentional — not ops infrastructure problems.
    if status == "failed" and err_msg and "severity policy failed" not in err_msg.lower():
        issues.append(f"scan failed: {err_msg[:400]}")
    for meta in engine_meta or []:
        if not isinstance(meta, dict):
            continue
        name = str(meta.get("engine") or "engine")
        skipped = meta.get("skipped")
        if isinstance(skipped, str) and skipped.strip():
            low = skipped.lower()
            if any(m in low for m in _EXPECTED_SKIP_MARKERS):
                pass
            elif any(m in low for m in _MISSING_MARKERS):
                issues.append(f"{name}: missing module — {skipped[:240]}")
            elif "error" in low or "failed" in low:
                issues.append(f"{name}: skipped — {skipped[:240]}")
        err = meta.get("error")
        if err:
            issues.append(f"{name}: error — {str(err)[:240]}")
    # Dedupe while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for item in issues:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _alert_ops(
    session,
    scan: Scan,
    project: Project,
    user: User | None,
    engine_meta: list[dict] | None = None,
) -> None:
    """Email ops inbox when engines are missing or the scan failed on the app side."""
    try:
        from app.services.email import send_ops_scan_alert

        issues = _collect_ops_issues(
            engine_meta,
            scan_status=scan.status,
            error_message=scan.error_message,
        )
        if not issues:
            return
        send_ops_scan_alert(
            session,
            project_name=project.name,
            project_id=project.id,
            scan_id=scan.id,
            status=scan.status or "unknown",
            owner_email=(user.email if user else None),
            issues=issues,
        )
        session.commit()
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass


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
                session.add(scan)
                session.commit()
                _set_progress(
                    session,
                    scan,
                    phase="cancelled",
                    percent=100,
                    eta_remaining=0,
                    log="Scan cancelled",
                )
                return

            scan.status = "running"
            scan.started_at = utcnow()
            scan.error_message = None
            session.add(scan)
            session.commit()

            engine_meta: list[dict] = []
            findings_out: list = []
            try:
                _set_progress(
                    session,
                    scan,
                    phase="cloning",
                    percent=5,
                    log="Pulling your repository…",
                    clear_logs=False,
                )
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
                    short = scan.commit_short or (scan.commit_sha or "")[:7]
                    _set_progress(
                        session,
                        scan,
                        phase="cloning",
                        percent=12,
                        log=f"Repository ready{f' @ {short}' if short else ''}",
                    )
                    if (scan.scan_scope or "full") == "changed":
                        base = project.github_default_branch or "main"
                        changed_paths = list_changed_files(repo_path, base_branch=base)
                        engine_meta.append({"engine": "diff", "changed_files": len(changed_paths), "base": base})
                        _set_progress(
                            session,
                            scan,
                            phase="cloning",
                            percent=15,
                            log=f"Scoped to {len(changed_paths)} changed file(s) vs {base}",
                        )
                else:
                    engine_meta.append({"engine": "clone", "skipped": "manual target — no GitHub clone"})
                    repo_path = None
                    _set_progress(
                        session,
                        scan,
                        phase="cloning",
                        percent=15,
                        log="No GitHub workspace — engines will be skipped",
                    )

                _check_cancel(session, scan)
                options = _parse_options(scan)
                enabled = set(options["engines"])
                excludes = options["path_excludes"]
                want_review = bool(options["code_review"]) or scan.scan_mode == "rules_plus_ai"

                if repo_path:
                    # Ordered pipeline. Percents are coarse milestones; live ETA uses elapsed/%.
                    engine_steps: list[tuple] = [
                        (
                            "gitleaks",
                            "secrets",
                            16,
                            20,
                            "Looking for exposed secrets…",
                            lambda: run_gitleaks(repo_path),
                            "Secret scan finished",
                            "No exposed secrets found",
                            "Found {n} potential secret exposure(s)",
                        ),
                        (
                            "trufflehog",
                            "secrets_deep",
                            22,
                            26,
                            "Deep secret hunt…",
                            lambda: run_trufflehog(repo_path),
                            "Deep secret scan finished",
                            "No additional secrets found",
                            "Found {n} deep secret finding(s)",
                        ),
                        (
                            "detect_secrets",
                            "secrets_entropy",
                            28,
                            32,
                            "Entropy secret scan…",
                            lambda: run_detect_secrets(repo_path),
                            "Entropy secret scan finished",
                            "No entropy secrets found",
                            "Found {n} entropy secret finding(s)",
                        ),
                        (
                            "osv",
                            "sca",
                            34,
                            38,
                            "Checking dependencies…",
                            lambda: run_osv(repo_path),
                            "Dependency check finished",
                            "No known vulnerable dependencies found",
                            "Found {n} dependency issue(s)",
                        ),
                        (
                            "pip_audit",
                            "sca_python",
                            40,
                            44,
                            "Auditing Python packages…",
                            lambda: run_pip_audit(repo_path),
                            "Python package audit finished",
                            "No pip-audit issues found",
                            "Found {n} Python package issue(s)",
                        ),
                        (
                            "trivy",
                            "sca_deep",
                            46,
                            50,
                            "Deep dependency & config check…",
                            lambda: run_trivy(repo_path),
                            "Deep SCA finished",
                            "No Trivy issues found",
                            "Found {n} Trivy finding(s)",
                        ),
                        (
                            "checkov",
                            "iac",
                            52,
                            56,
                            "Checking infrastructure as code…",
                            lambda: run_checkov(repo_path),
                            "IaC check finished",
                            "No Checkov issues found",
                            "Found {n} IaC issue(s)",
                        ),
                        (
                            "semgrep",
                            "semgrep",
                            58,
                            66,
                            "Reading through the code…",
                            lambda: run_semgrep(
                                repo_path,
                                security_level=scan.security_level,
                                include_paths=changed_paths,
                                excludes=excludes,
                            ),
                            "Code analysis finished",
                            "No code issues found in this pass",
                            "Found {n} code issue(s)",
                        ),
                        (
                            "bandit",
                            "bandit",
                            68,
                            72,
                            "Python security pass…",
                            lambda: run_bandit(repo_path),
                            "Python security pass finished",
                            "No Bandit issues found",
                            "Found {n} Python security issue(s)",
                        ),
                        (
                            "njsscan",
                            "nodejs",
                            74,
                            76,
                            "Node.js security pass…",
                            lambda: run_njsscan(repo_path),
                            "Node.js security pass finished",
                            "No njsscan issues found",
                            "Found {n} Node.js issue(s)",
                        ),
                        (
                            "hadolint",
                            "docker",
                            77,
                            78,
                            "Dockerfile review…",
                            lambda: run_hadolint(repo_path),
                            "Dockerfile review finished",
                            "No Dockerfile issues found",
                            "Found {n} Dockerfile issue(s)",
                        ),
                        (
                            "shellcheck",
                            "shell",
                            79,
                            80,
                            "Shell script review…",
                            lambda: run_shellcheck(repo_path),
                            "Shell review finished",
                            "No shell issues found",
                            "Found {n} shell issue(s)",
                        ),
                    ]

                    for (
                        eng_name,
                        phase,
                        pct_start,
                        pct_end,
                        start_log,
                        runner,
                        started_msg,
                        empty_msg,
                        found_msg,
                    ) in engine_steps:
                        _check_cancel(session, scan)
                        if eng_name not in enabled:
                            engine_meta.append({"engine": eng_name, "skipped": "disabled"})
                            continue
                        _set_progress(session, scan, phase=phase, percent=pct_start, log=start_log)
                        e_findings, e_meta = runner()
                        engine_meta.append(e_meta)
                        findings_out.extend(e_findings)
                        _log_engine_results(
                            session,
                            scan,
                            phase=phase,
                            percent=pct_end,
                            started_msg=started_msg,
                            empty_msg=empty_msg,
                            found_msg=found_msg,
                            findings=e_findings,
                        )

                    if want_review:
                        _check_cancel(session, scan)
                        _set_progress(
                            session,
                            scan,
                            phase="code_review",
                            percent=82,
                            log="AI code review in progress…",
                        )
                        r_findings, r_meta = review_repository(
                            repo_path,
                            include_paths=changed_paths,
                            excludes=excludes,
                        )
                        engine_meta.append(r_meta)
                        findings_out.extend(r_findings)
                        _log_engine_results(
                            session,
                            scan,
                            phase="code_review",
                            percent=88,
                            started_msg="AI review finished",
                            empty_msg="AI review added no extra findings",
                            found_msg="AI review flagged {n} issue(s)",
                            findings=r_findings,
                        )
                    else:
                        engine_meta.append({"engine": "openrouter_review", "skipped": "disabled"})

                    root = str(repo_path)
                    for nf in findings_out:
                        nf.file_path = public_repo_path(nf.file_path, repo_root=root)
                else:
                    for name in (*ALL_ENGINES, "openrouter_review"):
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
                    _set_progress(
                        session,
                        scan,
                        phase="reporting",
                        percent=90,
                        log="Writing the security report…",
                    )
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
                    _set_progress(
                        session,
                        scan,
                        phase="reporting",
                        percent=93,
                        log="Report draft ready",
                    )

                _check_cancel(session, scan)
                _set_progress(
                    session,
                    scan,
                    phase="reporting",
                    percent=95,
                    log=f"Saving {len(findings_out)} finding(s)…",
                )
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
                session.add(scan)
                session.commit()
                _set_progress(
                    session,
                    scan,
                    phase="failed" if policy_failed else "completed",
                    percent=100,
                    eta_remaining=0,
                    log=(
                        f"Policy failed — {open_count} open finding(s)"
                        if policy_failed
                        else f"Scan complete — {len(findings_out)} finding(s)"
                    ),
                )
                scan.eta_seconds = 0
                session.add(scan)
                session.commit()
                _notify(session, scan, project, user, summary)
                _alert_ops(session, scan, project, user, engine_meta)
            except ScanCancelled:
                scan.status = "cancelled"
                scan.error_message = "Scan cancelled by user."
                scan.finished_at = utcnow()
                session.add(scan)
                session.commit()
                _set_progress(
                    session,
                    scan,
                    phase="cancelled",
                    percent=100,
                    eta_remaining=0,
                    log="Scan cancelled",
                )
                scan.eta_seconds = 0
                session.add(scan)
                session.commit()
                _notify(session, scan, project, user, {"findings_count": 0})
            except CloneError as exc:
                scan.status = "failed"
                scan.error_message = str(exc)[:1000]
                scan.finished_at = utcnow()
                session.add(scan)
                session.commit()
                _set_progress(
                    session,
                    scan,
                    phase="failed",
                    percent=100,
                    eta_remaining=0,
                    log=f"Clone failed: {str(exc)[:160]}",
                )
                session.add(scan)
                session.commit()
                _notify(session, scan, project, user, {"findings_count": 0})
                _alert_ops(session, scan, project, user, engine_meta)
            except Exception as exc:
                scan.status = "failed"
                scan.error_message = str(exc)[:1000]
                scan.finished_at = utcnow()
                session.add(scan)
                session.commit()
                _set_progress(
                    session,
                    scan,
                    phase="failed",
                    percent=100,
                    eta_remaining=0,
                    log=f"Scan failed: {str(exc)[:160]}",
                )
                session.add(scan)
                session.commit()
                _notify(session, scan, project, user, {"findings_count": 0})
                _alert_ops(session, scan, project, user, engine_meta)
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
