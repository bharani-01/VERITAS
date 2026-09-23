from __future__ import annotations

import hashlib
import hmac
import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_secret
from app.core.database import db_session
from app.models import Project
from app.services import projects as project_svc

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _verify_signature(*, secret: str, body: bytes, signature_header: str | None) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    return hmac.compare_digest(expected, signature_header)


@router.post("/github")
async def github_webhook(
    request: Request,
    db: Session = Depends(db_session),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
):
    """GitHub push webhook — no session cookie. Verifies HMAC per project secret."""
    body = await request.body()
    if x_github_event == "ping":
        return {"ok": True, "pong": True}
    if x_github_event and x_github_event != "push":
        return {"ok": True, "skipped": "event", "event": x_github_event}

    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.") from exc

    repo = payload.get("repository") or {}
    repo_id = repo.get("id")
    if repo_id is None:
        return {"ok": True, "skipped": "no_repo"}

    # Match candidate projects that have this repo + auto-scan; verify signature against each secret.
    candidates = list(
        db.scalars(
            select(Project).where(
                Project.github_repo_id == int(repo_id),
                Project.auto_scan_on_push.is_(True),
            )
        )
    )
    if not candidates:
        return {"ok": True, "skipped": "no_project"}

    matched: Project | None = None
    for project in candidates:
        enc = getattr(project, "github_webhook_secret", None)
        if not enc:
            continue
        try:
            secret = decrypt_secret(enc)
        except ValueError:
            continue
        if _verify_signature(secret=secret, body=body, signature_header=x_hub_signature_256):
            matched = project
            break

    if not matched:
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    result = project_svc.handle_github_push_event(db, payload=payload)
    result["delivery"] = x_github_delivery
    return result
