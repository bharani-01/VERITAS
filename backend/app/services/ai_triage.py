"""Groq OpenAI-compatible AI triage for scan findings (fail-open)."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.core.config import GROQ_API_KEY, GROQ_MODEL, reload_env
from app.services.engines.normalize import NormalizedFinding

logger = logging.getLogger(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_MAX_FINDINGS = 25
_TIMEOUT = 45.0


def _api_key() -> str:
    reload_env()
    import os

    return (os.getenv("GROQ_API_KEY") or os.getenv("AI_API_KEY") or GROQ_API_KEY or "").strip()


def _model() -> str:
    reload_env()
    import os

    return (os.getenv("GROQ_MODEL") or GROQ_MODEL or "llama-3.3-70b-versatile").strip()


def triage_findings(findings: list[NormalizedFinding]) -> dict[str, Any]:
    """Annotate high/critical findings with ai_verdict / ai_rationale. Never raises."""
    key = _api_key()
    if not key:
        return {"status": "skipped_no_key", "triaged": 0}

    candidates = [f for f in findings if (f.severity or "").lower() in {"critical", "high"}][:_MAX_FINDINGS]
    if not candidates:
        return {"status": "skipped_none", "triaged": 0}

    payload_items = []
    for idx, f in enumerate(candidates):
        payload_items.append(
            {
                "i": idx,
                "title": (f.title or "")[:200],
                "severity": f.severity,
                "family": f.vuln_family,
                "engine": f.engine,
                "path": (f.file_path or "")[:200],
                "message": (f.message or "")[:400],
                "snippet": (f.snippet or "")[:400],
            }
        )

    system = (
        "You are a security triage assistant for SAST/SCA/secret findings. "
        "For each finding return JSON only: "
        '{"results":[{"i":0,"verdict":"likely_true|likely_false|needs_review","rationale":"short"}]} . '
        "Be conservative; prefer needs_review when unsure. No markdown."
    )
    user_msg = json.dumps({"findings": payload_items}, ensure_ascii=False)

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(
                GROQ_URL,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": _model(),
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_msg},
                    ],
                },
            )
        if resp.status_code >= 400:
            logger.warning("groq triage http %s: %s", resp.status_code, (resp.text or "")[:200])
            return {"status": "failed_http", "triaged": 0, "code": resp.status_code}

        body = resp.json()
        content = (((body.get("choices") or [{}])[0].get("message") or {}).get("content")) or "{}"
        parsed = json.loads(content)
        results = parsed.get("results") if isinstance(parsed, dict) else None
        if not isinstance(results, list):
            return {"status": "failed_parse", "triaged": 0}

        allowed = {"likely_true", "likely_false", "needs_review"}
        count = 0
        for row in results:
            if not isinstance(row, dict):
                continue
            try:
                i = int(row.get("i"))
            except (TypeError, ValueError):
                continue
            if i < 0 or i >= len(candidates):
                continue
            verdict = str(row.get("verdict") or "needs_review").lower()
            if verdict not in allowed:
                verdict = "needs_review"
            rationale = str(row.get("rationale") or "")[:1000]
            f = candidates[i]
            f.raw = {**(f.raw or {}), "ai_verdict": verdict, "ai_rationale": rationale}
            count += 1
        return {"status": "ok", "triaged": count}
    except Exception as exc:
        logger.warning("groq triage failed: %s", str(exc)[:200])
        return {"status": "failed_open", "triaged": 0, "error": str(exc)[:200]}
