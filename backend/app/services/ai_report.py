"""Groq final AI report + countermeasures (fail-open)."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from app.core.config import GROQ_API_KEY, GROQ_MODEL, reload_env
from app.services.engines.normalize import NormalizedFinding

logger = logging.getLogger(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_MAX_FINDINGS = 40
_TIMEOUT = 90.0


def _api_key() -> str:
    reload_env()
    return (os.getenv("GROQ_API_KEY") or os.getenv("AI_API_KEY") or GROQ_API_KEY or "").strip()


def _model() -> str:
    reload_env()
    return (os.getenv("GROQ_REPORT_MODEL") or os.getenv("GROQ_MODEL") or GROQ_MODEL or "openai/gpt-oss-120b").strip()


def generate_final_report(
    findings: list[NormalizedFinding],
    *,
    project_name: str,
    target: str,
    intel_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return {status, report_markdown, countermeasures_by_index}. Never raises."""
    key = _api_key()
    if not key:
        return {"status": "skipped_no_key", "report_markdown": None, "countermeasures": {}}

    ranked = sorted(
        findings,
        key=lambda f: (
            1 if (f.raw or {}).get("is_kev") else 0,
            float((f.raw or {}).get("effective_priority_score") or 0.0),
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((f.severity or "").lower(), 0),
        ),
        reverse=True,
    )[:_MAX_FINDINGS]

    if not ranked:
        md = (
            f"# VERITAS security summary\n\n"
            f"**Project:** {project_name}\n**Target:** {target}\n\n"
            f"No findings were reported by the scan engines.\n"
        )
        return {"status": "ok_empty", "report_markdown": md, "countermeasures": {}, "model": _model()}

    payload = []
    for i, f in enumerate(ranked):
        raw_meta = f.raw if isinstance(f.raw, dict) else {}
        payload.append(
            {
                "i": i,
                "title": (f.title or "")[:200],
                "severity": f.severity,
                "family": f.vuln_family,
                "engine": f.engine,
                "matched_engines": raw_meta.get("matched_engines") or [f.engine],
                "cve_id": raw_meta.get("cve_id"),
                "is_kev": bool(raw_meta.get("is_kev", False)),
                "epss_score": raw_meta.get("epss_score"),
                "priority_score": raw_meta.get("effective_priority_score"),
                "path": (f.file_path or "")[:200],
                "message": (f.message or "")[:400],
            }
        )

    system = (
        "You are a security engineer writing a VERITAS scan report. "
        "Return JSON only with shape: "
        '{"summary_markdown":"...","fixes":[{"i":0,"steps":["step1","step2"]}]} . '
        "summary_markdown MUST be GitHub-Flavored Markdown with real structure: "
        "start with '# VERITAS Scan Executive Summary', then '##' sections "
        "(Active Exploits & Threat Intelligence, Critical Issues, Themes, Prioritized Fixes, etc.), "
        "highlight any CISA KEV actively exploited CVEs, top EPSS probability scores, and cross-engine "
        "deduplication savings first, use '- ' bullet lists for findings and P1/P2 fixes (bold the priority label), "
        "and blank lines between sections. Keep steps concrete. No surrounding prose outside JSON."
    )
    user_msg = json.dumps(
        {
            "project": project_name,
            "target": target,
            "threat_intel_and_correlation": intel_summary or {},
            "findings": payload,
        },
        ensure_ascii=False,
    )

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(
                GROQ_URL,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": _model(),
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_msg},
                    ],
                },
            )
        if resp.status_code >= 400:
            logger.warning("groq report http %s: %s", resp.status_code, (resp.text or "")[:200])
            return {"status": "failed_http", "report_markdown": None, "countermeasures": {}, "code": resp.status_code}

        body = resp.json()
        content = (((body.get("choices") or [{}])[0].get("message") or {}).get("content")) or "{}"
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return {"status": "failed_parse", "report_markdown": None, "countermeasures": {}}

        report = str(parsed.get("summary_markdown") or "").strip()[:20000]
        fixes_raw = parsed.get("fixes") if isinstance(parsed.get("fixes"), list) else []
        countermeasures: dict[int, list[str]] = {}
        for row in fixes_raw:
            if not isinstance(row, dict):
                continue
            try:
                i = int(row.get("i"))
            except (TypeError, ValueError):
                continue
            steps = row.get("steps")
            if isinstance(steps, list) and steps:
                countermeasures[i] = [str(s)[:400] for s in steps[:8]]

        # Apply onto ranked findings raw for callers that map by index
        for i, steps in countermeasures.items():
            if 0 <= i < len(ranked):
                ranked[i].raw = {
                    **(ranked[i].raw or {}),
                    "ai_fix_steps": steps,
                }

        if not report:
            report = f"# VERITAS security summary\n\nReviewed {len(ranked)} finding(s) for **{project_name}**.\n"

        return {
            "status": "ok",
            "report_markdown": report,
            "countermeasures": countermeasures,
            "model": _model(),
            "findings_in_report": len(ranked),
        }
    except Exception as exc:
        logger.warning("groq report failed: %s", str(exc)[:200])
        return {
            "status": "failed_open",
            "report_markdown": None,
            "countermeasures": {},
            "error": str(exc)[:200],
        }
