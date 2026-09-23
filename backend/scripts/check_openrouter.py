"""One-shot OpenRouter connectivity check. Does not print secrets."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / ".env"


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


def main() -> int:
    vals = load_env(ENV)
    key = (vals.get("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_API_KEY") or "").strip()
    model = (vals.get("OPENROUTER_REVIEW_MODEL") or "openai/gpt-4o-mini").strip()
    print(f"env_file={ENV.exists()}")
    print(f"key_present={bool(key and len(key) > 8)}")
    print(f"model={model}")
    if not key:
        print("result=SKIPPED_NO_KEY")
        return 2

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": 'Reply with JSON only: {"ok":true,"engine":"openrouter_review"}',
            },
            {"role": "user", "content": "ping"},
        ],
        "temperature": 0,
        "max_tokens": 48,
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://veritas.trackifyapp.co.in",
        "X-Title": "VERITAS",
    }
    try:
        r = httpx.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=45.0,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"result=NETWORK_ERROR")
        print(f"error={type(exc).__name__}: {exc}")
        return 1

    print(f"http_status={r.status_code}")
    try:
        data = r.json()
    except Exception:
        print("result=BAD_JSON")
        print(f"body_preview={(r.text or '')[:200]}")
        return 1

    err = data.get("error")
    if err:
        msg = err.get("message") if isinstance(err, dict) else err
        print(f"result=API_ERROR")
        print(f"error={msg}")
        return 1

    content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    print(f"has_choices={bool(data.get('choices'))}")
    print(f"content_preview={content[:160].replace(chr(10), ' ')}")
    print("result=OK" if r.status_code == 200 and content else "result=EMPTY")
    return 0 if r.status_code == 200 and content else 1


if __name__ == "__main__":
    sys.exit(main())
