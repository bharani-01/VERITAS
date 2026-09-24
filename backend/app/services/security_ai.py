"""AI agent for live HTTP security countermeasures (Groq → OpenRouter fail-open)."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from app.core.config import GROQ_API_KEY, GROQ_MODEL, OPENROUTER_API_KEY, OPENROUTER_REVIEW_MODEL, reload_env

logger = logging.getLogger(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_TIMEOUT = 45.0


def _groq_key() -> str:
    reload_env()
    return (os.getenv("GROQ_API_KEY") or os.getenv("AI_API_KEY") or GROQ_API_KEY or "").strip()


def _openrouter_key() -> str:
    reload_env()
    return (os.getenv("OPENROUTER_API_KEY") or OPENROUTER_API_KEY or "").strip()


def _provider() -> tuple[str, str, str, dict[str, str]] | None:
    """Return (name, url, model, headers) or None if no key configured."""
    groq = _groq_key()
    if groq:
        model = (
            os.getenv("GROQ_REPORT_MODEL") or os.getenv("GROQ_MODEL") or GROQ_MODEL or "openai/gpt-oss-120b"
        ).strip()
        return (
            "groq",
            GROQ_URL,
            model,
            {"Authorization": f"Bearer {groq}", "Content-Type": "application/json"},
        )
    or_key = _openrouter_key()
    if or_key:
        model = (os.getenv("OPENROUTER_REVIEW_MODEL") or OPENROUTER_REVIEW_MODEL or "openai/gpt-4o-mini").strip()
        return (
            "openrouter",
            OPENROUTER_URL,
            model,
            {
                "Authorization": f"Bearer {or_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": (os.getenv("PUBLIC_APP_URL") or "https://veritas.trackifyapp.co.in").rstrip("/"),
                "X-Title": "VERITAS Security Agent",
            },
        )
    return None


def analyze_http_security(context: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze recent HTTP telemetry and return countermeasure suggestions.
    Prefers Groq; falls back to OpenRouter. Never raises.
    """
    provider = _provider()
    if not provider:
        return {
            "status": "skipped_no_key",
            "summary": "AI analysis is unavailable — configure GROQ_API_KEY or OPENROUTER_API_KEY.",
            "suggestions": [],
        }

    name, url, model, headers = provider

    system = (
        "You are VERITAS Security Agent, a senior application security engineer. "
        "You analyze live HTTP request telemetry (metadata only: method, path, status, "
        "classification, severity, signals — no bodies or secrets). "
        "Return JSON only with shape: "
        '{"summary":"2-4 sentence situation assessment",'
        '"suggestions":[{"title":"short title","family":"sqli|xss|csrf|auth_anomaly|general",'
        '"priority":"critical|high|medium|low","steps":["actionable step", "..."]}]} . '
        "Prioritize concrete, VERITAS-app-specific countermeasures. "
        "If traffic looks clean, still suggest 1-2 hardening steps. "
        "No markdown fences, no prose outside JSON."
    )
    user_msg = json.dumps(context, ensure_ascii=False)[:12000]

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(
                url,
                headers=headers,
                json={
                    "model": model,
                    "temperature": 0.25,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_msg},
                    ],
                },
            )
        if resp.status_code >= 400:
            logger.warning("security ai (%s) http %s: %s", name, resp.status_code, (resp.text or "")[:200])
            return {
                "status": "failed_http",
                "summary": f"AI agent request failed via {name} (HTTP {resp.status_code}).",
                "suggestions": [],
                "code": resp.status_code,
                "provider": name,
            }

        body = resp.json()
        content = (((body.get("choices") or [{}])[0].get("message") or {}).get("content")) or "{}"
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return {"status": "failed_parse", "summary": "AI returned an unexpected response.", "suggestions": []}

        summary = str(parsed.get("summary") or "").strip()[:2000]
        raw_suggestions = parsed.get("suggestions") if isinstance(parsed.get("suggestions"), list) else []
        suggestions: list[dict[str, Any]] = []
        for row in raw_suggestions[:8]:
            if not isinstance(row, dict):
                continue
            steps = row.get("steps")
            if not isinstance(steps, list) or not steps:
                continue
            family = str(row.get("family") or "general")[:32]
            priority = str(row.get("priority") or "medium").lower()[:16]
            if priority not in ("critical", "high", "medium", "low"):
                priority = "medium"
            suggestions.append(
                {
                    "title": str(row.get("title") or "Recommendation")[:120],
                    "family": family,
                    "priority": priority,
                    "steps": [str(s)[:400] for s in steps[:6]],
                }
            )

        if not summary:
            summary = "Analysis complete." if suggestions else "No specific risks stood out in the sampled traffic."

        return {
            "status": "ok",
            "summary": summary,
            "suggestions": suggestions,
            "model": model,
            "provider": name,
        }
    except Exception as exc:
        logger.warning("security ai (%s) failed: %s", name, str(exc)[:200])
        return {
            "status": "failed_open",
            "summary": "AI agent could not complete analysis. Try again shortly.",
            "suggestions": [],
            "error": str(exc)[:200],
            "provider": name,
        }
