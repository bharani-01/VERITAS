"""Ping OpenRouter + Groq models. Never prints secrets."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx

ENV = Path(__file__).resolve().parents[1] / ".env"


def load_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        k, _, v = raw.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def ping(
    name: str,
    url: str,
    key: str,
    model: str,
    headers_extra: dict[str, str] | None = None,
) -> None:
    print(f"\n=== {name} ===")
    print(f"model={model}")
    print(f"key_present={bool(key and len(key) > 8)}")
    if not key:
        print("result=SKIPPED_NO_KEY")
        return
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        **(headers_extra or {}),
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": 'Reply with JSON only: {"ok":true}'},
            {"role": "user", "content": "ping"},
        ],
        "temperature": 0,
        "max_tokens": 40,
    }
    try:
        r = httpx.post(url, headers=headers, json=payload, timeout=45.0)
    except Exception as exc:  # noqa: BLE001
        print(f"result=NETWORK_ERROR error={type(exc).__name__}: {exc}")
        return
    print(f"http_status={r.status_code}")
    try:
        data = r.json()
    except Exception:
        print(f"result=BAD_JSON body={(r.text or '')[:160]}")
        return
    err = data.get("error")
    if err:
        msg = err.get("message") if isinstance(err, dict) else err
        print(f"result=API_ERROR error={msg}")
        return
    content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    print(f"content_preview={content[:120].replace(chr(10), ' ')}")
    print("result=OK" if r.status_code == 200 and content else "result=EMPTY")


def main() -> int:
    vals = load_env(ENV)
    or_key = (vals.get("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_API_KEY") or "").strip()
    or_model = (vals.get("OPENROUTER_REVIEW_MODEL") or "openai/gpt-4o-mini").strip()
    groq_key = (vals.get("GROQ_API_KEY") or vals.get("AI_API_KEY") or os.getenv("GROQ_API_KEY") or "").strip()
    groq_model = (
        vals.get("GROQ_REPORT_MODEL") or vals.get("GROQ_MODEL") or "llama-3.3-70b-versatile"
    ).strip()

    ping(
        "OpenRouter (Jev-style code review)",
        "https://openrouter.ai/api/v1/chat/completions",
        or_key,
        or_model,
        {
            "HTTP-Referer": "https://veritas.trackifyapp.co.in",
            "X-Title": "VERITAS",
        },
    )
    ping(
        "Groq (final report)",
        "https://api.groq.com/openai/v1/chat/completions",
        groq_key,
        groq_model,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
