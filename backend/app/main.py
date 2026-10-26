from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.encoders import ENCODERS_BY_TYPE
from sqlalchemy import create_engine, select

from app.api import admin as admin_api
from app.api import auth as auth_api
from app.api import public as public_api
from app.api import webhooks as webhooks_api
from app.api import workspace as workspace_api
from app.core import database as database
from app.core.config import APP_ENV, reload_env
from app.core.database import SessionLocal, engine
from app.core.time import to_iso_utc
from app.models import Base, User, apply_phase6a_schema_migrations
from app.services.auth import bootstrap_admin, ensure_schema
from app.services.github import github_config_report
from app.services.http_middleware import HttpTelemetryMiddleware
from app.services.scan_runner import ensure_scan_worker
from app.services.tokens import issue_token
from app.web.routes import mount_static, router as web_router

# SQLite returns naive UTC; without this, JSON omits the offset and browsers treat
# timestamps as local time (e.g. IST), so "ago" and wall-clock labels drift.
ENCODERS_BY_TYPE[datetime] = to_iso_utc

DATABASE_URL = database.DATABASE_URL


@asynccontextmanager
async def lifespan(_: FastAPI):
    reload_env()
    report = github_config_report()
    print(f"[VERITAS] GitHub integration: configured={report['configured']} missing={report['missing']} env_file={report['env_file_found']}", flush=True)
    Base.metadata.create_all(bind=database.engine)
    apply_phase6a_schema_migrations(database.engine)
    ensure_schema()
    bootstrap_admin()
    ensure_scan_worker()

    if APP_ENV != "test":
        import threading
        from app.services.threat_intel import sync_threat_intel_feeds

        def _daily_threat_intel_loop() -> None:
            import time
            while True:
                try:
                    with database.SessionLocal() as session:
                        sync_threat_intel_feeds(session)
                except Exception:
                    pass
                time.sleep(86400)

        threading.Thread(target=_daily_threat_intel_loop, name="veritas-threat-intel", daemon=True).start()

    yield


app = FastAPI(title="VERITAS Identity API", version="0.2.0", lifespan=lifespan)
app.add_middleware(HttpTelemetryMiddleware)
mount_static(app)


@app.get("/health")
def health():
    """Lightweight API liveness for admin monitoring UI."""
    from app.core.time import utcnow

    db_ok = False
    try:
        with database.SessionLocal() as session:
            session.execute(select(1))
            db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "api": "up",
        "database": "up" if db_ok else "down",
        "server_time": utcnow(),
        "version": app.version,
    }


app.include_router(auth_api.router)
app.include_router(admin_api.router)
app.include_router(workspace_api.router)
app.include_router(public_api.router)
app.include_router(webhooks_api.router)
app.include_router(web_router)

__all__ = [
    "app",
    "DATABASE_URL",
    "SessionLocal",
    "engine",
    "create_engine",
    "select",
    "User",
    "issue_token",
    "database",
]
