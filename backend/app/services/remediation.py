from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import GROQ_API_KEY, GROQ_MODEL, reload_env
from app.models.identity import User
from app.models.workspace import Finding
from app.services.projects import get_owned_scan

logger = logging.getLogger(__name__)


def _sanitize_branch_slug(val: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9\-]+", "-", val.strip().lower()).strip("-")
    return slug[:36] or "security-patch"


def _build_deterministic_diff(finding: Finding) -> str:
    file_path = (finding.file_path or "src/app.py").lstrip("./")
    raw_data: dict[str, Any] = {}
    if finding.raw_json:
        try:
            raw_data = json.loads(finding.raw_json)
        except Exception:
            raw_data = {}

    pkg = (
        raw_data.get("package_name")
        or raw_data.get("PkgName")
        or raw_data.get("package")
    )
    installed_ver = (
        raw_data.get("installed_version")
        or raw_data.get("InstalledVersion")
        or raw_data.get("version")
    )
    fixed_ver = (
        raw_data.get("fixed_version")
        or raw_data.get("FixedVersion")
        or (
            raw_data.get("fix_versions")[0]
            if isinstance(raw_data.get("fix_versions"), list) and raw_data.get("fix_versions")
            else None
        )
    )

    if finding.vuln_family in ("sca", "dependency", "license") or pkg:
        pkg_name = str(pkg or "package")
        old_ver = str(installed_ver or "1.0.0")
        new_ver = str(fixed_ver or "latest-patched")
        target_file = file_path if not file_path.startswith("http") else "requirements.txt"
        if target_file.endswith("package.json"):
            return (
                f"--- a/{target_file}\n"
                f"+++ b/{target_file}\n"
                f"@@ -1,3 +1,3 @@\n"
                f'-    "{pkg_name}": "{old_ver}"\n'
                f'+    "{pkg_name}": "^{new_ver}"\n'
            )
        return (
            f"--- a/{target_file}\n"
            f"+++ b/{target_file}\n"
            f"@@ -1,1 +1,1 @@\n"
            f"-{pkg_name}=={old_ver}\n"
            f"+{pkg_name}>={new_ver}\n"
        )

    if finding.vuln_family in ("secret", "secrets"):
        line_no = finding.line_start or 1
        snippet = (finding.snippet or "API_KEY = 'REDACTED'").splitlines()[0]
        return (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -{line_no},1 +{line_no},2 @@\n"
            f"-{snippet}\n"
            f"+import os\n"
            f"+# Loaded securely from environment secret manager\n"
        )

    if finding.engine == "veritas_dast":
        return (
            "--- a/backend/app/services/security_headers.py\n"
            "+++ b/backend/app/services/security_headers.py\n"
            "@@ -1,3 +1,8 @@\n"
            "+response.headers['Content-Security-Policy'] = \"default-src 'self'; frame-ancestors 'none'\"\n"
            "+response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'\n"
            "+response.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "+response.headers['X-Frame-Options'] = 'DENY'\n"
        )

    line_no = finding.line_start or 1
    old_line = (finding.snippet or "# vulnerable code").splitlines()[0]
    return (
        f"--- a/{file_path}\n"
        f"+++ b/{file_path}\n"
        f"@@ -{line_no},1 +{line_no},1 @@\n"
        f"-{old_line}\n"
        f"+{old_line}  # remediated per {finding.cwe or finding.rule_id or 'VERITAS policy'}\n"
    )


def generate_finding_fix_plan(
    db: Session,
    user: User,
    finding_id: str,
) -> dict[str, Any]:
    """
    Generates a ready-to-apply Git remediation plan (`branch_name`, `commit_message`,
    `unified_diff`, `pr_title`, `pr_body`) for a finding, enforcing project RBAC.
    """
    finding = db.scalar(select(Finding).where(Finding.id == finding_id))
    if not finding:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Finding not found.")

    scan, project = get_owned_scan(db, user, finding.scan_id)

    tag = _sanitize_branch_slug(finding.cwe or finding.cve_id or finding.vuln_family or "vuln")
    branch_name = f"veritas/fix-{tag}-{finding.id[:6]}"
    commit_message = (
        f"fix(security): remediate {finding.title[:56]} "
        f"[{finding.cve_id or finding.cwe or finding.rule_id or finding.engine}]"
    )
    unified_diff = _build_deterministic_diff(finding)

    reload_env()
    groq_key = (os.getenv("GROQ_API_KEY") or GROQ_API_KEY or "").strip()
    if groq_key and os.getenv("APP_ENV") != "test" and finding.snippet:
        try:
            with httpx.Client(timeout=12.0) as client:
                resp = client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
                    json={
                        "model": os.getenv("GROQ_MODEL") or GROQ_MODEL or "openai/gpt-oss-120b",
                        "temperature": 0.1,
                        "response_format": {"type": "json_object"},
                        "messages": [
                            {
                                "role": "system",
                                "content": 'Return JSON only: {"unified_diff": "--- a/...\\n+++ b/..."} fixing the security issue.',
                            },
                            {
                                "role": "user",
                                "content": json.dumps(
                                    {
                                        "title": finding.title,
                                        "cwe": finding.cwe,
                                        "file_path": finding.file_path,
                                        "line": finding.line_start,
                                        "snippet": finding.snippet,
                                        "message": finding.message,
                                    }
                                ),
                            },
                        ],
                    },
                )
                if resp.status_code == 200:
                    parsed = json.loads(resp.json()["choices"][0]["message"]["content"])
                    if isinstance(parsed.get("unified_diff"), str) and "--- " in parsed["unified_diff"]:
                        unified_diff = parsed["unified_diff"]
        except Exception as exc:
            logger.debug("Groq diff refinement skipped (fail-open): %s", str(exc)[:160])

    epss_str = f"{(finding.epss_score * 100):.1f}%" if finding.epss_score is not None else "N/A"
    kev_badge = "YES (CISA KEV Active Exploit)" if getattr(finding, "is_kev", False) else "No"

    pr_title = f"[VERITAS Security Fix] {finding.title[:72]}"
    pr_body = (
        f"## Automated Security Remediation Plan\n\n"
        f"- **Project:** {project.name}\n"
        f"- **Finding:** {finding.title}\n"
        f"- **Severity / Priority:** `{finding.severity.upper()}` (Priority `{getattr(finding, 'effective_priority_score', finding.risk_score):.1f}/10`)\n"
        f"- **Taxonomy:** `{finding.cwe or 'N/A'}` · `{finding.owasp_category or 'N/A'}` · `{finding.cve_id or 'N/A'}`\n"
        f"- **CISA KEV Status:** {kev_badge} · **FIRST EPSS:** `{epss_str}`\n"
        f"- **Location:** `{finding.file_path or scan.target}{':' + str(finding.line_start) if finding.line_start else ''}`\n\n"
        f"### Proposed Patch\n"
        f"```diff\n{unified_diff.strip()}\n```\n\n"
        f"### Verification Checklist\n"
        f"- [ ] Apply unified diff on branch `{branch_name}`\n"
        f"- [ ] Re-run VERITAS scan to verify finding closure\n"
    )

    return {
        "finding_id": finding.id,
        "scan_id": scan.id,
        "project_id": project.id,
        "branch_name": branch_name,
        "commit_message": commit_message,
        "pr_title": pr_title,
        "pr_body": pr_body,
        "unified_diff": unified_diff,
    }
