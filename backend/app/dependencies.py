"""Compatibility wrapper for app.dependencies."""

from app.api.deps import db_session as get_db, get_current_user, require_admin as require_admin_user

__all__ = ["get_current_user", "require_admin_user", "get_db"]
