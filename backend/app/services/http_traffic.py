"""Persist and prune HTTP request telemetry."""

from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.time import utcnow
from app.models import AuthSession, HttpRequestEvent
from app.core.security import token_hash
from app.services.http_classifier import (
    ATTACK_FAMILIES,
    classify_request,
    sanitize_path,
    should_track,
)

__all__ = ("ATTACK_FAMILIES", "record_http_event", "serialize_http_event", "maybe_prune")

RETENTION_DAYS = 7
MAX_ROWS = 50_000
_PRUNE_EVERY = 200
_write_count = 0


def resolve_actor_id(db: Session, session_cookie: str | None) -> str | None:
    if not session_cookie:
        return None
    try:
        row = db.scalar(
            select(AuthSession).where(
                AuthSession.token_hash == token_hash(session_cookie),
                AuthSession.revoked_at.is_(None),
            )
        )
        if not row:
            return None
        if row.expires_at and row.expires_at < utcnow():
            return None
        return row.user_id
    except Exception:
        return None


def record_http_event(
    db: Session,
    *,
    method: str,
    path: str,
    query: str | None,
    status_code: int,
    duration_ms: int,
    ip_address: str | None,
    user_agent: str | None,
    session_cookie: str | None,
    origin: str | None,
    referer: str | None,
    request_host: str | None,
    header_blob: str | None = None,
    response_headers: dict[str, str] | None = None,
) -> None:
    if not should_track(path):
        return

    safe_path = sanitize_path(path, query)
    classification, severity, signals = classify_request(
        method=method,
        path=path,
        query=query,
        status_code=status_code,
        has_session_cookie=bool(session_cookie),
        origin=origin,
        referer=referer,
        request_host=request_host,
        user_agent=user_agent,
        header_blob=header_blob,
        response_headers=response_headers,
    )
    actor_id = resolve_actor_id(db, session_cookie)
    ua = (user_agent or "")[:512] or None
    db.add(
        HttpRequestEvent(
            method=(method or "GET").upper()[:16],
            path=safe_path,
            status_code=int(status_code),
            duration_ms=max(0, int(duration_ms)),
            ip_address=(ip_address or None),
            user_agent=ua,
            actor_user_id=actor_id,
            classification=classification,
            severity=severity,
            signals=json.dumps(signals) if signals else None,
        )
    )
    db.commit()
    maybe_prune(db)


def maybe_prune(db: Session) -> None:
    global _write_count
    _write_count += 1
    if _write_count % _PRUNE_EVERY != 0:
        return
    cutoff = utcnow() - timedelta(days=RETENTION_DAYS)
    db.execute(delete(HttpRequestEvent).where(HttpRequestEvent.created_at < cutoff))
    total = db.scalar(select(func.count()).select_from(HttpRequestEvent)) or 0
    if total > MAX_ROWS:
        overflow = total - MAX_ROWS
        oldest_ids = list(
            db.scalars(
                select(HttpRequestEvent.id).order_by(HttpRequestEvent.created_at.asc()).limit(overflow)
            )
        )
        if oldest_ids:
            db.execute(delete(HttpRequestEvent).where(HttpRequestEvent.id.in_(oldest_ids)))
    db.commit()


def serialize_http_event(event: HttpRequestEvent) -> dict:
    signals = []
    if event.signals:
        try:
            signals = json.loads(event.signals)
        except json.JSONDecodeError:
            signals = [event.signals]
    return {
        "id": event.id,
        "method": event.method,
        "path": event.path,
        "status_code": event.status_code,
        "duration_ms": event.duration_ms,
        "ip_address": event.ip_address,
        "user_agent": event.user_agent,
        "actor_user_id": event.actor_user_id,
        "classification": event.classification,
        "severity": event.severity,
        "signals": signals,
        "created_at": event.created_at,
    }
