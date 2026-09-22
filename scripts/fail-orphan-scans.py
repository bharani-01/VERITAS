#!/usr/bin/env python3
"""One-shot: fail orphaned running/queued scans that lost the in-memory worker."""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine, text

ROOT = Path("/opt/veritas/backend")
env: dict[str, str] = {}
for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
    raw = line.strip()
    if not raw or raw.startswith("#") or "=" not in raw:
        continue
    key, _, val = raw.partition("=")
    env[key.strip()] = val.strip().strip('"').strip("'")

url = env.get("DATABASE_URL") or f"sqlite:///{(ROOT / env.get('SQLITE_PATH', 'app.db')).resolve()}"
eng = create_engine(url)
failed_progress = json.dumps(
    {"phase": "failed", "label": "Something went wrong", "percent": 100, "eta_remaining_seconds": 0}
)
with eng.begin() as conn:
    rows = conn.execute(
        text(
            "SELECT id, status, progress_json, created_at FROM scans "
            "WHERE status IN ('running', 'queued') ORDER BY created_at DESC"
        )
    ).mappings().all()
    print(f"orphans={len(rows)}")
    for r in rows:
        print(dict(r))
    updated = conn.execute(
        text(
            "UPDATE scans SET status='failed', "
            "error_message=:msg, finished_at=CURRENT_TIMESTAMP, progress_json=:prog, eta_seconds=0 "
            "WHERE status IN ('running', 'queued')"
        ),
        {
            "msg": "Scan interrupted by a server restart. Start the scan again.",
            "prog": failed_progress,
        },
    )
    print(f"updated={updated.rowcount}")
