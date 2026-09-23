from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC (SQLite) and normalize aware values to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_iso_utc(value: datetime) -> str:
    """Serialize for JSON so browsers parse as UTC (always ends with Z)."""
    return ensure_utc(value).isoformat().replace("+00:00", "Z")


def is_expired(value: datetime) -> bool:
    """Compare timestamps consistently across SQLite (naive) and PostgreSQL (aware)."""
    return ensure_utc(value) <= utcnow()
