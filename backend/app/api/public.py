from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import db_session
from app.services import projects as project_svc

router = APIRouter(prefix="/public", tags=["public"])


@router.get("/reports/{token}")
def public_shared_report(token: str, db: Session = Depends(db_session)):
    """Unauthenticated view of a shared scan report (read-only)."""
    return project_svc.get_shared_report(db, token)
