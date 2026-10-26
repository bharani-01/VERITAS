from __future__ import annotations

import json
from sqlalchemy.orm import Session

from app.models.workspace import Finding, FindingSuppression, Scan
from app.services.correlator import correlate_findings
from app.services.engines.trivy_sbom import generate_and_persist_sbom
from app.services.threat_intel import (
    build_executive_intel_context,
    enrich_findings_with_intel,
)


def execute_phase6a_post_processing(
    db: Session,
    scan: Scan,
    repo_workdir: str,
    raw_engine_findings: list[dict],
    auto_fetch_missing_epss: bool = True,
) -> tuple[list[Finding], dict]:
    """
    Invoked by ScanWorker after all 12 security engines finish scanning `repo_workdir`:
      1. Generates & persists the CycloneDX 1.5 SBOM and appends any restricted copyleft
         `trivy_license` findings to `raw_engine_findings`.
      2. Correlates & deduplicates findings across all engines while honoring `FindingSuppression`.
      3. Enriches CVE findings with CISA KEV and FIRST EPSS scores and computes `effective_priority_score`.
      4. Persists canonical `Finding` rows sorted by priority and returns the Groq executive context.
    """
    # Step 1: CycloneDX SBOM + License Governance
    sbom_result = generate_and_persist_sbom(
        db=db,
        scan_id=scan.id,
        project_id=scan.project_id,
        repo_workdir=repo_workdir,
    )
    combined_raw_findings = list(raw_engine_findings) + list(sbom_result.license_findings)

    # Step 2: Load active project suppressions
    suppressed_fps = {
        row.fingerprint
        for row in db.query(FindingSuppression)
        .filter(FindingSuppression.project_id == scan.project_id)
        .all()
        if row.fingerprint
    }

    # Step 3: Cross-Engine Canonical Correlation
    correlation_summary = correlate_findings(
        raw_findings=combined_raw_findings,
        suppressed_fingerprints=suppressed_fps,
    )

    # Step 4: Offline CISA KEV + FIRST EPSS Enrichment & Priority Scoring
    enriched_dicts = enrich_findings_with_intel(
        db=db,
        findings=correlation_summary.findings,
        auto_fetch_missing_epss=auto_fetch_missing_epss,
    )

    # Step 5: Persist canonical Finding ORM objects
    persisted_findings: list[Finding] = []
    for item in enriched_dicts:
        matched_engines = item.get("matched_engines") or [item.get("engine") or "unknown"]
        finding_row = Finding(
            scan_id=scan.id,
            project_id=scan.project_id,
            engine=str(item.get("engine") or matched_engines[0]),
            category=str(item.get("category") or "sast"),
            severity=str(item.get("severity") or "medium"),
            title=str(item.get("title") or "Security Finding"),
            description=str(item.get("description") or ""),
            file_path=str(item.get("file_path") or "unknown"),
            line_number=int(item.get("line_number") or 0),
            cwe=item.get("cwe"),
            owasp=item.get("owasp"),
            code_snippet=item.get("code_snippet") or item.get("snippet"),
            countermeasure=item.get("remediation") or item.get("countermeasure"),
            fingerprint=str(item.get("fingerprint") or ""),
            status="false_positive" if item.get("is_suppressed") else str(item.get("status") or "open"),
            is_suppressed=bool(item.get("is_suppressed", False)),
            # Phase 6A fields:
            cve_id=item.get("cve_id"),
            matched_engines_json=json.dumps(matched_engines),
            engine_count=int(item.get("engine_count") or len(matched_engines)),
            confidence_level=str(item.get("confidence_level") or "medium"),
            epss_score=item.get("epss_score"),
            epss_percentile=item.get("epss_percentile"),
            is_kev=bool(item.get("is_kev", False)),
            kev_due_date=item.get("kev_due_date"),
            effective_priority_score=float(item.get("effective_priority_score") or 0.0),
        )
        db.add(finding_row)
        persisted_findings.append(finding_row)

    # Update Scan correlation counters if present on Scan model
    if hasattr(scan, "raw_findings_count"):
        scan.raw_findings_count = correlation_summary.raw_findings_count
    if hasattr(scan, "correlated_findings_count"):
        scan.correlated_findings_count = correlation_summary.correlated_findings_count
    if hasattr(scan, "kev_findings_count"):
        scan.kev_findings_count = sum(1 for f in enriched_dicts if f.get("is_kev"))

    db.commit()
    for f_row in persisted_findings:
        db.refresh(f_row)

    # Step 6: Build Executive Intelligence Summary for Groq (`services/ai_report.py`)
    exec_intel_context = build_executive_intel_context(
        raw_findings_count=correlation_summary.raw_findings_count,
        correlated_findings=enriched_dicts,
    )
    return persisted_findings, exec_intel_context
