from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import create_engine, select

from app.api import admin as admin_api
from app.api import auth as auth_api
from app.api import workspace as workspace_api
from app.core import database as database
from app.core.config import reload_env
from app.core.database import SessionLocal, engine
from app.models import Base, User
from app.services.auth import bootstrap_admin, ensure_schema
from app.services.github import github_config_report
from app.services.tokens import issue_token
from app.web.routes import mount_static, router as web_router

DATABASE_URL = database.DATABASE_URL


@asynccontextmanager
async def lifespan(_: FastAPI):
    reload_env()
    report = github_config_report()
    print(f"[VERITAS] GitHub integration: configured={report['configured']} missing={report['missing']} env_file={report['env_file_found']}", flush=True)
    Base.metadata.create_all(bind=database.engine)
    ensure_schema()
    bootstrap_admin()
    yield


app = FastAPI(title="VERITAS Identity API", version="0.2.0", lifespan=lifespan)
mount_static(app)
app.include_router(auth_api.router)
app.include_router(admin_api.router)
app.include_router(workspace_api.router)
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
