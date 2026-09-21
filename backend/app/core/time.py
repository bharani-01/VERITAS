from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_expired(value: datetime) -> bool:
    """Compare timestamps consistently across SQLite (naive) and PostgreSQL (aware)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= utcnow()
