from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session


class RateLimiter:
    def __init__(self) -> None:
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int) -> None:
        now = time.monotonic()
        bucket = self.events[key]
        while bucket and bucket[0] < now - window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(status_code=429, detail="Please wait before trying again.")
        bucket.append(now)


rate_limiter = RateLimiter()


def check_rate_limit(
    db: Session,
    request: Request,
    key: str,
    limit: int,
    window_seconds: int,
) -> None:
    """Enforce rate limit and record a 429 audit event when blocked."""
    try:
        rate_limiter.check(key, limit, window_seconds)
    except HTTPException as exc:
        if exc.status_code == 429:
            from app.services.audit import audit

            audit(
                db,
                request,
                "rate_limited",
                after={"scope": key.split(":", 1)[0]},
                status_code=429,
            )
            db.commit()
        raise
