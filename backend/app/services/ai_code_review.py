"""OpenRouter Jev-style structured code review (fail-open)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx

from app.core.config import reload_env
from app.services.engines.normalize import NormalizedFinding, normalize_severity

logger = logging.getLogger(__name__)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_MAX_FILES = 8
_MAX_CHARS = 6000
_TIMEOUT = 60.0

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    "target",
    "coverage",
}
_CODE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".kt",
    ".swift",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".sh",
    ".ps1",
    ".yml",
    ".yaml",
    ".json",
    ".env",
    ".toml",
}


def _api_key() -> str:
    reload_env()
    return (os.getenv("OPENROUTER_API_KEY") or "").strip()


def _model() -> str:
    reload_env()
    return (os.getenv("OPENROUTER_REVIEW_MODEL") or "openai/gpt-4o-mini").strip()


def _path_excluded(rel: str, excludes: list[str] | None) -> bool:
    if not excludes:
        return False
    norm = rel.replace("\\", "/")
    for pattern in excludes:
        p = (pattern or "").strip().replace("\\", "/")
        if not p:
            continue
        if p.endswith("/**") and norm.startswith(p[:-3]):
            return True
        if p.endswith("/**/") and norm.startswith(p[:-4]):
            return True
        if "*" in p:
            # simple suffix / prefix wildcards
            if p.startswith("*.") and norm.endswith(p[1:]):
                return True
            if p.endswith("/**") and f"/{p[:-3].rstrip('/')}/" in f"/{norm}/":
                return True
        if norm == p or norm.startswith(p.rstrip("/") + "/"):
            return True
        if p in norm:
            return True
    return False


def _pick_files(
    repo_path: Path,
    *,
    include_paths: list[str] | None = None,
    excludes: list[str] | None = None,
) -> list[Path]:
    picked: list[Path] = []
    if include_paths is not None:
        for rel in include_paths:
            if _path_excluded(rel, excludes):
                continue
            candidate = repo_path / rel
            if candidate.is_file() and candidate.suffix.lower() in _CODE_SUFFIXES:
                picked.append(candidate)
            if len(picked) >= _MAX_FILES:
                break
        return picked

    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(repo_path).parts)
        if parts & _SKIP_DIRS:
            continue
        rel = str(path.relative_to(repo_path)).replace("\\", "/")
        if _path_excluded(rel, excludes):
            continue
        if path.suffix.lower() not in _CODE_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 80_000:
                continue
        except OSError:
            continue
        picked.append(path)
        if len(picked) >= _MAX_FILES:
            break
    return picked


def _severity_from_score(score: float) -> str:
    if score >= 3.5:
        return "critical"
    if score >= 2.5:
        return "high"
    if score >= 1.5:
        return "medium"
    if score >= 0.75:
        return "low"
    return "info"


def review_repository(
    repo_path: Path,
    *,
    include_paths: list[str] | None = None,
    excludes: list[str] | None = None,
) -> tuple[list[NormalizedFinding], dict[str, Any]]:
    """Structured code review via OpenRouter. Never raises."""
    meta: dict[str, Any] = {"engine": "openrouter_review", "available": False}
    key = _api_key()
    if not key:
        meta["skipped"] = "OPENROUTER_API_KEY not set"
        return [], meta

    files = _pick_files(repo_path, include_paths=include_paths, excludes=excludes)
    if not files:
        meta["available"] = True
        meta["skipped"] = "no reviewable files"
        meta["findings"] = 0
        return [], meta

    file_payload = []
    for path in files:
        rel = str(path.relative_to(repo_path)).replace("\\", "/")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:_MAX_CHARS]
        except OSError:
            continue
        file_payload.append({"path": rel, "content": text})

    if not file_payload:
        meta["available"] = True
        meta["skipped"] = "unreadable files"
        return [], meta

    meta["available"] = True
    meta["model"] = _model()
    meta["files_reviewed"] = len(file_payload)

    system = (
        "You are a security code reviewer. For each file return structured JSON only:\n"
        '{"reviews":[{"path":"rel/path","risk_score":0-4,"category":'
        '"secret|injection|auth|supply_chain|malware|other|clean",'
        '"suspicious":true|false,"title":"short","rationale":"one sentence"}]}\n'
        "risk_score: 0 clean … 4 critical. Prefer clean/false when unsure. No markdown."
    )
    user_msg = json.dumps({"files": file_payload}, ensure_ascii=False)

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://veritas.local",
                    "X-Title": "VERITAS",
                },
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
            logger.warning("openrouter review http %s: %s", resp.status_code, (resp.text or "")[:200])
            meta["skipped"] = f"http_{resp.status_code}"
            return [], meta

        body = resp.json()
        content = (((body.get("choices") or [{}])[0].get("message") or {}).get("content")) or "{}"
        parsed = json.loads(content)
        reviews = parsed.get("reviews") if isinstance(parsed, dict) else None
        if not isinstance(reviews, list):
            meta["skipped"] = "failed_parse"
            return [], meta

        findings: list[NormalizedFinding] = []
        for row in reviews:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path") or "")[:1024]
            if not path:
                continue
            try:
                score = float(row.get("risk_score") or 0)
            except (TypeError, ValueError):
                score = 0.0
            suspicious = bool(row.get("suspicious"))
            category = str(row.get("category") or "other").lower()
            if category == "clean" and not suspicious and score < 1.0:
                continue
            if score < 1.0 and not suspicious:
                continue
            severity = normalize_severity(_severity_from_score(score))
            family = {
                "secret": "secret",
                "injection": "sqli" if "sql" in str(row.get("title") or "").lower() else "other",
                "auth": "other",
                "supply_chain": "sca",
                "malware": "other",
            }.get(category, "other")
            title = str(row.get("title") or f"Code review · {category}")[:512]
            rationale = str(row.get("rationale") or "")[:1000]
            findings.append(
                NormalizedFinding(
                    engine="openrouter_review",
                    title=title,
                    severity=severity,
                    rule_id=f"openrouter/{category}",
                    vuln_family=family,
                    message=rationale,
                    file_path=path,
                    snippet=rationale[:500],
                    raw={
                        "risk_score": score,
                        "category": category,
                        "suspicious": suspicious,
                        "ai_verdict": "likely_true" if suspicious or score >= 2 else "needs_review",
                        "ai_rationale": rationale,
                    },
                )
            )
        meta["findings"] = len(findings)
        meta["status"] = "ok"
        return findings, meta
    except Exception as exc:
        logger.warning("openrouter review failed: %s", str(exc)[:200])
        meta["skipped"] = "failed_open"
        meta["error"] = str(exc)[:200]
        return [], meta
