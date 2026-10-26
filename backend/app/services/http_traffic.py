"""Persist and prune HTTP request telemetry + Active IPS Auto-Quarantine."""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core import database as db
from app.core.security import token_hash
from app.core.time import ensure_utc, utcnow
from app.models import AuthSession, BlockedIp, HttpRequestEvent
from app.services.http_classifier import (
    ATTACK_FAMILIES,
    classify_request,
    sanitize_path,
    should_track,
)

logger = logging.getLogger(__name__)

__all__ = (
    "ATTACK_FAMILIES",
    "record_http_event",
    "serialize_http_event",
    "maybe_prune",
    "refresh_blocked_ip_cache",
    "is_ip_quarantined",
    "block_ip_address",
    "unblock_ip_address",
    "list_blocked_ips",
)

RETENTION_DAYS = 7
MAX_ROWS = 50_000
_PRUNE_EVERY = 200
_write_count = 0

IPS_WINDOW_SECONDS = 60
IPS_ATTACK_THRESHOLD = 5
IPS_QUARANTINE_MINUTES = 60
IPS_TRIGGER_FAMILIES = {"sqli", "xss", "cmd_inject", "path_traversal", "ssrf", "ssti"}

_IPS_LOCK = threading.Lock()
_BLOCKED_IP_CACHE: dict[str, tuple[float | None, str]] = {}
_CACHE_LAST_SYNC: float = 0.0


def refresh_blocked_ip_cache(session: Session | None = None) -> None:
    """Syncs active `BlockedIp` rows into the in-memory lookup table."""
    global _CACHE_LAST_SYNC
    own_session = session is None
    sess = session or db.SessionLocal()
    try:
        now = utcnow()
        rows = list(sess.scalars(select(BlockedIp)).all())
        new_map: dict[str, tuple[float | None, str]] = {}
        for r in rows:
            exp = ensure_utc(r.expires_at) if r.expires_at else None
            if exp and exp < now:
                continue
            exp_ts = exp.timestamp() if exp else None
            new_map[r.ip_address] = (exp_ts, r.reason)
        with _IPS_LOCK:
            _BLOCKED_IP_CACHE.clear()
            _BLOCKED_IP_CACHE.update(new_map)
            _CACHE_LAST_SYNC = time.monotonic()
    except Exception as exc:
        logger.debug("BlockedIp cache refresh skipped: %s", exc)
    finally:
        if own_session:
            sess.close()


def is_ip_quarantined(ip: str | None) -> tuple[bool, str | None]:
    if not ip:
        return False, None
    now_mono = time.monotonic()
    if now_mono - _CACHE_LAST_SYNC > 5.0:
        refresh_blocked_ip_cache()

    now_epoch = utcnow().timestamp()
    with _IPS_LOCK:
        entry = _BLOCKED_IP_CACHE.get(ip)
        if not entry:
            return False, None
        exp_ts, reason = entry
        if exp_ts is not None and now_epoch > exp_ts:
            _BLOCKED_IP_CACHE.pop(ip, None)
            return False, None
        return True, reason


def block_ip_address(
    session: Session,
    *,
    ip_address: str,
    reason: str,
    attack_category: str = "manual",
    hit_count: int = 1,
    expires_in_minutes: int | None = IPS_QUARANTINE_MINUTES,
    created_by: str = "admin",
) -> BlockedIp:
    clean_ip = ip_address.strip()[:64]
    now = utcnow()
    expires_at = (
        now + timedelta(minutes=int(expires_in_minutes))
        if expires_in_minutes is not None and int(expires_in_minutes) > 0
        else None
    )
    row = session.scalar(select(BlockedIp).where(BlockedIp.ip_address == clean_ip))
    if row is None:
        row = BlockedIp(
            ip_address=clean_ip,
            reason=reason[:512],
            attack_category=attack_category[:64],
            hit_count=hit_count,
            blocked_at=now,
            expires_at=expires_at,
            created_by=created_by[:64],
        )
        session.add(row)
    else:
        row.reason = reason[:512]
        row.attack_category = attack_category[:64]
        row.hit_count = max(row.hit_count, hit_count)
        row.blocked_at = now
        row.expires_at = expires_at
        row.created_by = created_by[:64]
        session.add(row)

    session.commit()
    session.refresh(row)
    refresh_blocked_ip_cache(session)
    return row


def unblock_ip_address(session: Session, ip_address: str) -> bool:
    clean_ip = ip_address.strip()[:64]
    row = session.scalar(select(BlockedIp).where(BlockedIp.ip_address == clean_ip))
    if not row:
        with _IPS_LOCK:
            _BLOCKED_IP_CACHE.pop(clean_ip, None)
        return False
    session.delete(row)
    session.commit()
    with _IPS_LOCK:
        _BLOCKED_IP_CACHE.pop(clean_ip, None)
    return True


def list_blocked_ips(session: Session) -> list[dict]:
    now = utcnow()
    rows = list(session.scalars(select(BlockedIp).order_by(BlockedIp.blocked_at.desc())).all())
    out: list[dict] = []
    for r in rows:
        exp = ensure_utc(r.expires_at) if r.expires_at else None
        is_active = exp is None or exp > now
        out.append(
            {
                "ip_address": r.ip_address,
                "reason": r.reason,
                "attack_category": r.attack_category,
                "hit_count": r.hit_count,
                "blocked_at": ensure_utc(r.blocked_at).isoformat() if r.blocked_at else None,
                "expires_at": exp.isoformat() if exp else None,
                "created_by": r.created_by,
                "active": is_active,
            }
        )
    return out


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

    now = utcnow()
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
    clean_ip = (ip_address or "").strip()[:64] or None
    db.add(
        HttpRequestEvent(
            method=(method or "GET").upper()[:16],
            path=safe_path,
            status_code=int(status_code),
            duration_ms=max(0, int(duration_ms)),
            ip_address=clean_ip,
            user_agent=ua,
            actor_user_id=actor_id,
            classification=classification,
            severity=severity,
            signals=json.dumps(signals) if signals else None,
        )
    )
    db.commit()

    # Phase 6C Active IPS: if IP triggered >= 5 attack heuristics within 60 seconds, auto-quarantine
    if clean_ip and classification in IPS_TRIGGER_FAMILIES:
        window_start = now - timedelta(seconds=IPS_WINDOW_SECONDS)
        recent_hits = (
            db.scalar(
                select(func.count(HttpRequestEvent.id)).where(
                    HttpRequestEvent.ip_address == clean_ip,
                    HttpRequestEvent.classification.in_(sorted(IPS_TRIGGER_FAMILIES)),
                    HttpRequestEvent.created_at >= window_start,
                )
            )
            or 0
        )
        if int(recent_hits) >= IPS_ATTACK_THRESHOLD:
            block_ip_address(
                db,
                ip_address=clean_ip,
                reason=(
                    f"Auto-quarantined by VERITAS Active IPS after {recent_hits} "
                    f"attack payloads (latest: {classification})"
                ),
                attack_category=classification,
                hit_count=int(recent_hits),
                expires_in_minutes=IPS_QUARANTINE_MINUTES,
                created_by="auto_ips",
            )

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
