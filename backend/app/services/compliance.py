from __future__ import annotations

import html
import re
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.time import ensure_utc, utcnow
from app.models.workspace import Finding, FindingSuppression, Project, Scan, ScanSbomArtifact

CWE_NUM_REGEX = re.compile(r"(\d{1,5})")

OWASP_TOP_10_CONTROLS: list[dict[str, Any]] = [
    {
        "id": "A01:2021",
        "title": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are properly enforced.",
        "cwes": {22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275},
        "families": {"csrf", "idor", "authz", "path_traversal"},
    },
    {
        "id": "A02:2021",
        "title": "Cryptographic Failures",
        "description": "Protection of sensitive data in transit and at rest using strong cryptographic algorithms.",
        "cwes": {261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916},
        "families": {"crypto", "tls"},
    },
    {
        "id": "A03:2021",
        "title": "Injection",
        "description": "User-supplied data is validated, filtered, or sanitized to prevent SQL, NoSQL, OS command, and XSS injection.",
        "cwes": {20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917},
        "families": {"sqli", "xss", "cmdi", "injection"},
    },
    {
        "id": "A04:2021",
        "title": "Insecure Design",
        "description": "Threat modeling, secure design patterns, and reference architectures are enforced.",
        "cwes": {73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173},
        "families": {"design", "business_logic"},
    },
    {
        "id": "A05:2021",
        "title": "Security Misconfiguration",
        "description": "Secure hardening across cloud IaC, containers, Dockerfiles, HTTP headers, and permissions.",
        "cwes": {2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 732, 756, 776, 942, 1004, 1032, 1174},
        "families": {"iac", "misconfig", "container", "dockerfile"},
    },
    {
        "id": "A06:2021",
        "title": "Vulnerable and Outdated Components",
        "description": "Third-party libraries, dependencies, and open-source licenses are inventoried and free of known exploits.",
        "cwes": {937, 1035, 1104},
        "families": {"sca", "dependency", "license"},
    },
    {
        "id": "A07:2021",
        "title": "Identification and Authentication Failures",
        "description": "Zero hardcoded credentials/secrets, robust session management, and strong authentication.",
        "cwes": {255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216},
        "families": {"secret", "secrets", "auth"},
    },
    {
        "id": "A08:2021",
        "title": "Software and Data Integrity Failures",
        "description": "CI/CD pipeline integrity, safe deserialization, and verified software supply chain updates.",
        "cwes": {345, 353, 426, 494, 502, 565, 784, 829, 830, 915},
        "families": {"deserialization", "integrity"},
    },
    {
        "id": "A09:2021",
        "title": "Security Logging and Monitoring Failures",
        "description": "Auditable security events, log injection prevention, and alerting on active exploitation.",
        "cwes": {117, 223, 532, 778},
        "families": {"logging"},
    },
    {
        "id": "A10:2021",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "Remote resource fetches validate and restrict destination URLs and network layers.",
        "cwes": {918},
        "families": {"ssrf"},
    },
]

SOC2_CONTROLS: list[dict[str, Any]] = [
    {
        "id": "CC6.1",
        "title": "Logical Access Security & Secret Hygiene",
        "description": "Logical access and credentials are protected against unauthorized disclosure or hardcoded tokens.",
        "owasp_refs": {"A01:2021", "A02:2021", "A07:2021"},
    },
    {
        "id": "CC6.6",
        "title": "System Boundary & Infrastructure-as-Code Protection",
        "description": "External system boundaries, containers, and IaC templates are securely configured.",
        "owasp_refs": {"A05:2021", "A10:2021"},
    },
    {
        "id": "CC6.8",
        "title": "Software Supply Chain & SBOM Governance",
        "description": "Third-party software components and open-source licenses are tracked via SBOM and governed.",
        "owasp_refs": {"A06:2021", "A08:2021"},
    },
    {
        "id": "CC7.1",
        "title": "Vulnerability Detection & Code Security",
        "description": "Static analysis (SAST) detects injection, insecure design, and application vulnerabilities.",
        "owasp_refs": {"A03:2021", "A04:2021"},
    },
    {
        "id": "CC7.2",
        "title": "Active Threat Monitoring & CISA KEV Remediation",
        "description": "Actively exploited vulnerabilities (CISA KEV) and high-EPSS risks are remediated within SLA.",
        "owasp_refs": {"A09:2021"},
        "match_kev_or_sla": True,
    },
    {
        "id": "CC8.1",
        "title": "Change Management & Pre-Production Verification",
        "description": "Automated multi-engine security checks verify code changes prior to production deployment.",
        "owasp_refs": {"A04:2021", "A08:2021"},
    },
]

ISO27001_CONTROLS: list[dict[str, Any]] = [
    {
        "id": "A.8.7",
        "title": "Protection Against Malware & Malicious Packages",
        "description": "Supply chain dependencies are inspected for known malicious or compromised packages.",
        "owasp_refs": {"A06:2021", "A08:2021"},
    },
    {
        "id": "A.8.8",
        "title": "Management of Technical Vulnerabilities",
        "description": "Timely identification and patching of technical CVEs, CISA KEV items, and high-EPSS risks.",
        "owasp_refs": {"A06:2021"},
        "match_kev_or_sla": True,
    },
    {
        "id": "A.8.9",
        "title": "Configuration Management",
        "description": "Security configurations for cloud infrastructure, containers, and OS scripts are enforced.",
        "owasp_refs": {"A05:2021"},
    },
    {
        "id": "A.8.20",
        "title": "Networks & Boundary Security",
        "description": "Protection against SSRF, broken access control, and unencrypted network transmission.",
        "owasp_refs": {"A01:2021", "A02:2021", "A10:2021"},
    },
    {
        "id": "A.8.25",
        "title": "Secure Development Life Cycle",
        "description": "Security requirements, secret scanning, and architectural reviews are integrated into SDLC.",
        "owasp_refs": {"A04:2021", "A07:2021", "A09:2021"},
    },
    {
        "id": "A.8.28",
        "title": "Secure Coding",
        "description": "Secure coding principles prevent injection (SQLi, XSS, Command Injection) and memory/logic flaws.",
        "owasp_refs": {"A03:2021"},
    },
    {
        "id": "A.5.36",
        "title": "Compliance with Policies & Software Licenses",
        "description": "Adherence to open-source license policies (prevention of unauthorized GPL/AGPL/SSPL usage).",
        "match_license_only": True,
    },
]


def compute_finding_sla(
    project: Project,
    *,
    severity: str | None,
    is_kev: bool = False,
    base_time=None,
) -> tuple[Any, bool]:
    """
    Computes `(sla_due_at, sla_breached)` for a finding based on the project's SLA policy.
    """
    now = utcnow()
    ref_time = ensure_utc(base_time) if base_time else now
    sev = "critical" if is_kev else (severity or "info").lower()

    if sev == "critical":
        days = int(getattr(project, "sla_critical_days", 7) or 7)
    elif sev == "high":
        days = int(getattr(project, "sla_high_days", 14) or 14)
    elif sev == "medium":
        days = int(getattr(project, "sla_medium_days", 30) or 30)
    else:
        days = int(getattr(project, "sla_low_days", 90) or 90)

    due_at = ref_time + timedelta(days=max(1, days))
    breached = now > due_at
    return due_at, breached


def _extract_cwe_number(cwe_str: str | None) -> int | None:
    if not cwe_str:
        return None
    m = CWE_NUM_REGEX.search(str(cwe_str))
    return int(m.group(1)) if m else None


def map_finding_to_owasp_ids(f: Finding) -> set[str]:
    matched: set[str] = set()
    owasp_cat = (f.owasp_category or "").upper()
    for ctrl in OWASP_TOP_10_CONTROLS:
        cid = ctrl["id"]
        if cid in owasp_cat or cid.split(":")[0] in owasp_cat:
            matched.add(cid)

    cwe_num = _extract_cwe_number(f.cwe)
    fam = (f.vuln_family or "").lower()
    eng = (f.engine or "").lower()

    if fam == "license" or eng == "trivy_license" or cwe_num == 1104:
        matched.add("A06:2021")
    if fam in ("sca", "dependency") or eng in ("osv", "pip_audit") or getattr(f, "cve_id", None) or getattr(f, "is_kev", False):
        matched.add("A06:2021")
    if fam in ("secret", "secrets") or eng in ("gitleaks", "trufflehog", "detect_secrets"):
        matched.add("A07:2021")
    if eng in ("checkov", "hadolint") or fam in ("iac", "container", "dockerfile"):
        matched.add("A05:2021")
    if fam == "sqli" or fam == "xss":
        matched.add("A03:2021")
    if fam == "csrf":
        matched.add("A01:2021")

    for ctrl in OWASP_TOP_10_CONTROLS:
        if cwe_num and cwe_num in ctrl["cwes"]:
            matched.add(ctrl["id"])
        if fam and fam in ctrl["families"]:
            matched.add(ctrl["id"])

    if not matched:
        matched.add("A04:2021")

    return matched


def _score_controls(
    controls_spec: list[dict[str, Any]],
    findings_by_control: dict[str, list[Finding]],
) -> dict[str, Any]:
    evaluated_controls: list[dict[str, Any]] = []
    total_points = 0.0
    pass_count = 0
    warn_count = 0
    fail_count = 0

    for spec in controls_spec:
        cid = spec["id"]
        matched = findings_by_control.get(cid, [])
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        has_kev = False
        for f in matched:
            sev = (f.severity or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
            if getattr(f, "is_kev", False):
                has_kev = True

        if counts["critical"] > 0 or counts["high"] > 0 or has_kev:
            status = "fail"
            fail_count += 1
            points = 0.0
        elif counts["medium"] > 0 or counts["low"] > 0 or counts["info"] > 0:
            status = "warn"
            warn_count += 1
            points = 0.6
        else:
            status = "pass"
            pass_count += 1
            points = 1.0

        total_points += points
        evaluated_controls.append(
            {
                "control_id": cid,
                "title": spec["title"],
                "description": spec["description"],
                "status": status,
                "finding_count": len(matched),
                "finding_counts": counts,
                "sample_findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "cwe": f.cwe,
                        "cve_id": getattr(f, "cve_id", None),
                        "is_kev": bool(getattr(f, "is_kev", False)),
                        "file_path": f.file_path,
                    }
                    for f in matched[:5]
                ],
            }
        )

    total_controls = len(controls_spec) or 1
    readiness_score = round((total_points / total_controls) * 100.0, 1)
    if fail_count == 0 and readiness_score >= 85.0:
        verdict = "Audit Ready"
    elif fail_count <= 2 and readiness_score >= 60.0:
        verdict = "Needs Remediation"
    else:
        verdict = "Critical Non-Compliance"

    return {
        "readiness_score": readiness_score,
        "verdict": verdict,
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "total_controls": len(controls_spec),
        "controls": evaluated_controls,
    }


def evaluate_scan_compliance(
    db: Session,
    project: Project,
    scan: Scan,
) -> dict[str, Any]:
    """
    Evaluates a scan's open findings and SBOM artifact against OWASP Top 10:2021,
    SOC 2 Type II, and ISO/IEC 27001:2022 Annex A, plus SLA & suppression metrics.
    """
    all_findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all())
    active_findings = [f for f in all_findings if f.status in ("open", "triage")]

    now = utcnow()
    overdue_sla_count = 0
    kev_open_count = 0

    for f in active_findings:
        if getattr(f, "is_kev", False):
            kev_open_count += 1
        due = ensure_utc(f.sla_due_at) if getattr(f, "sla_due_at", None) else None
        if due is None:
            due, breached = compute_finding_sla(
                project,
                severity=f.severity,
                is_kev=bool(getattr(f, "is_kev", False)),
                base_time=f.created_at,
            )
        else:
            breached = now > due
        if breached:
            overdue_sla_count += 1

    sbom_artifact = db.scalar(
        select(ScanSbomArtifact).where(ScanSbomArtifact.scan_id == scan.id)
    )
    pending_suppressions_count = len(
        list(
            db.scalars(
                select(FindingSuppression).where(
                    FindingSuppression.project_id == project.id,
                    FindingSuppression.status == "pending_approval",
                )
            ).all()
        )
    )

    owasp_buckets: dict[str, list[Finding]] = {c["id"]: [] for c in OWASP_TOP_10_CONTROLS}
    for f in active_findings:
        for owasp_id in map_finding_to_owasp_ids(f):
            owasp_buckets.setdefault(owasp_id, []).append(f)

    soc2_buckets: dict[str, list[Finding]] = {c["id"]: [] for c in SOC2_CONTROLS}
    for spec in SOC2_CONTROLS:
        cid = spec["id"]
        seen_ids: set[str] = set()
        for owasp_ref in spec.get("owasp_refs", set()):
            for f in owasp_buckets.get(owasp_ref, []):
                if f.id not in seen_ids:
                    seen_ids.add(f.id)
                    soc2_buckets[cid].append(f)
        if spec.get("match_kev_or_sla"):
            for f in active_findings:
                if (getattr(f, "is_kev", False) or getattr(f, "sla_breached", False)) and f.id not in seen_ids:
                    seen_ids.add(f.id)
                    soc2_buckets[cid].append(f)

    iso_buckets: dict[str, list[Finding]] = {c["id"]: [] for c in ISO27001_CONTROLS}
    for spec in ISO27001_CONTROLS:
        cid = spec["id"]
        seen_ids = set()
        if spec.get("match_license_only"):
            for f in active_findings:
                cwe_num = _extract_cwe_number(f.cwe)
                if f.vuln_family == "license" or f.engine == "trivy_license" or cwe_num == 1104:
                    if f.id not in seen_ids:
                        seen_ids.add(f.id)
                        iso_buckets[cid].append(f)
            continue

        for owasp_ref in spec.get("owasp_refs", set()):
            for f in owasp_buckets.get(owasp_ref, []):
                if f.id not in seen_ids:
                    seen_ids.add(f.id)
                    iso_buckets[cid].append(f)
        if spec.get("match_kev_or_sla"):
            for f in active_findings:
                if (getattr(f, "is_kev", False) or getattr(f, "sla_breached", False)) and f.id not in seen_ids:
                    seen_ids.add(f.id)
                    iso_buckets[cid].append(f)

    owasp_eval = _score_controls(OWASP_TOP_10_CONTROLS, owasp_buckets)
    soc2_eval = _score_controls(SOC2_CONTROLS, soc2_buckets)
    iso_eval = _score_controls(ISO27001_CONTROLS, iso_buckets)

    overall_score = round(
        (owasp_eval["readiness_score"] + soc2_eval["readiness_score"] + iso_eval["readiness_score"]) / 3.0,
        1,
    )
    if overall_score >= 85.0 and kev_open_count == 0:
        overall_verdict = "Audit Ready"
    elif overall_score >= 60.0 and kev_open_count == 0:
        overall_verdict = "Needs Remediation"
    else:
        overall_verdict = "Critical Non-Compliance"

    return {
        "scan_id": scan.id,
        "project_id": project.id,
        "project_name": project.name,
        "target": scan.target,
        "commit_sha": scan.commit_sha,
        "evaluated_at": now.isoformat(),
        "overall_readiness_score": overall_score,
        "overall_verdict": overall_verdict,
        "total_open_findings": len(active_findings),
        "total_suppressed_findings": len(all_findings) - len(active_findings),
        "kev_open_count": kev_open_count,
        "total_overdue_sla": overdue_sla_count,
        "pending_suppressions_count": pending_suppressions_count,
        "sbom_verified": sbom_artifact is not None,
        "sbom_component_count": sbom_artifact.component_count if sbom_artifact else 0,
        "sbom_policy_violations": sbom_artifact.policy_violations_count if sbom_artifact else 0,
        "frameworks": {
            "owasp_top_10": {
                "name": "OWASP Top 10 (2021)",
                **owasp_eval,
            },
            "soc2": {
                "name": "SOC 2 Type II (Trust Services Criteria)",
                **soc2_eval,
            },
            "iso27001": {
                "name": "ISO/IEC 27001:2022 Annex A",
                **iso_eval,
            },
        },
    }


def render_compliance_certificate_html(compliance_data: dict[str, Any]) -> str:
    """
    Renders a print-styled, self-contained HTML/PDF-ready Enterprise Compliance Audit Certificate.
    """
    proj_name = html.escape(str(compliance_data.get("project_name") or "Project"))
    scan_id = html.escape(str(compliance_data.get("scan_id") or ""))
    target = html.escape(str(compliance_data.get("target") or ""))
    commit = html.escape(str(compliance_data.get("commit_sha") or "HEAD")[:12])
    evaluated_at = html.escape(str(compliance_data.get("evaluated_at") or ""))
    overall_score = compliance_data.get("overall_readiness_score", 0.0)
    overall_verdict = html.escape(str(compliance_data.get("overall_verdict") or ""))

    frameworks = compliance_data.get("frameworks") or {}

    def _render_framework_table(fw_key: str) -> str:
        fw = frameworks.get(fw_key) or {}
        rows_html = []
        for ctrl in fw.get("controls") or []:
            st = str(ctrl.get("status") or "pass").upper()
            badge_cls = "status-pass" if st == "PASS" else ("status-warn" if st == "WARN" else "status-fail")
            rows_html.append(
                f"<tr>"
                f"<td><code>{html.escape(str(ctrl.get('control_id')))}</code></td>"
                f"<td><strong>{html.escape(str(ctrl.get('title')))}</strong><br/>"
                f"<span class='desc'>{html.escape(str(ctrl.get('description')))}</span></td>"
                f"<td><span class='badge {badge_cls}'>{st}</span></td>"
                f"<td>{int(ctrl.get('finding_count') or 0)}</td>"
                f"</tr>"
            )
        return (
            f"<section class='fw-section'>"
            f"<h2>{html.escape(str(fw.get('name')))} — Readiness: {fw.get('readiness_score')}% ({html.escape(str(fw.get('verdict')))})</h2>"
            f"<table><thead><tr><th>Control ID</th><th>Control Objective</th><th>Status</th><th>Open Findings</th></tr></thead>"
            f"<tbody>{''.join(rows_html)}</tbody></table>"
            f"</section>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>VERITAS Compliance Audit Certificate — {proj_name}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; margin: 32px; line-height: 1.5; }}
    .cert-header {{ border-bottom: 3px solid #1e3a8a; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }}
    h1 {{ margin: 0 0 6px 0; font-size: 24px; color: #0f172a; }}
    h2 {{ font-size: 16px; margin-top: 24px; color: #1e293b; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
    .summary-card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; background: #f8fafc; }}
    .summary-card .label {{ font-size: 12px; color: #475569; text-transform: uppercase; }}
    .summary-card .val {{ font-size: 20px; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; font-weight: 600; }}
    .desc {{ color: #475569; font-size: 12px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
    .status-pass {{ background: #dcfce7; color: #166534; }}
    .status-warn {{ background: #fef3c7; color: #92400e; }}
    .status-fail {{ background: #fee2e2; color: #991b1b; }}
    .signoff {{ margin-top: 36px; padding-top: 16px; border-top: 1px dashed #94a3b8; display: flex; justify-content: space-between; font-size: 12px; color: #475569; }}
    @media print {{
      body {{ margin: 12mm; }}
      .fw-section {{ page-break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <div class="cert-header">
    <div>
      <h1>VERITAS DevSecOps Compliance Audit Certificate</h1>
      <div><strong>Project:</strong> {proj_name} &middot; <strong>Target:</strong> {target} &middot; <strong>Commit:</strong> <code>{commit}</code></div>
      <div><strong>Scan ID:</strong> <code>{scan_id}</code> &middot; <strong>Evaluated At:</strong> {evaluated_at}</div>
    </div>
    <div style="text-align: right;">
      <div style="font-size: 28px; font-weight: 800; color: #1e3a8a;">{overall_score}%</div>
      <div style="font-size: 13px; font-weight: 700;">{overall_verdict}</div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="label">Open Findings</div>
      <div class="val">{int(compliance_data.get('total_open_findings') or 0)}</div>
    </div>
    <div class="summary-card">
      <div class="label">CISA KEV Active Exploits</div>
      <div class="val">{int(compliance_data.get('kev_open_count') or 0)}</div>
    </div>
    <div class="summary-card">
      <div class="label">SLA Breaches</div>
      <div class="val">{int(compliance_data.get('total_overdue_sla') or 0)}</div>
    </div>
    <div class="summary-card">
      <div class="label">CycloneDX 1.5 SBOM</div>
      <div class="val">{'Verified (' + str(compliance_data.get('sbom_component_count', 0)) + ' pkgs)' if compliance_data.get('sbom_verified') else 'Not Generated'}</div>
    </div>
  </div>

  {_render_framework_table('owasp_top_10')}
  {_render_framework_table('soc2')}
  {_render_framework_table('iso27001')}

  <div class="signoff">
    <div>Attested by <strong>VERITAS Automated Compliance Engine v2.1 (Phase 6B)</strong></div>
    <div>Authorized Security Lead Signature: ___________________________</div>
  </div>
</body>
</html>"""
