"""Compatibility wrapper for app.database."""

from app.core.database import SessionLocal, db_session as get_db, engine
from app.models.base import Base

__all__ = ["Base", "get_db", "engine", "SessionLocal"]
