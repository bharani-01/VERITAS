from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import DATABASE_URL
from app.models.base import Base

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def reload_engine(url: str | None = None):
    global DATABASE_URL, engine, SessionLocal
    if url:
        DATABASE_URL = url
    c_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    engine.dispose()
    engine = create_engine(DATABASE_URL, connect_args=c_args, future=True)
    SessionLocal.configure(bind=engine)
    return engine


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
