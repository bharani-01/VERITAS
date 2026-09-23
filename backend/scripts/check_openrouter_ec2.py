"""Ping OpenRouter using /opt/veritas/backend/.env (EC2)."""
from __future__ import annotations

from pathlib import Path

import httpx

ENV = Path("/opt/veritas/backend/.env")


def main() -> None:
    vals: dict[str, str] = {}
    for line in ENV.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        vals[k.strip()] = v.strip().strip('"').strip("'")
    key = vals.get("OPENROUTER_API_KEY", "")
    model = vals.get("OPENROUTER_REVIEW_MODEL") or "openai/gpt-4o-mini"
    print(f"env_file={ENV.exists()}")
    print(f"key_present={bool(key and len(key) > 8)}")
    print(f"model={model}")
    if not key:
        print("result=SKIPPED_NO_KEY")
        return
    r = httpx.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://veritas.trackifyapp.co.in",
            "X-Title": "VERITAS",
        },
        json={
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 20,
            "temperature": 0,
        },
        timeout=45.0,
    )
    print(f"http_status={r.status_code}")
    content = ((r.json().get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    print(f"result={'OK' if r.status_code == 200 and content else 'FAIL'}")


if __name__ == "__main__":
    main()
