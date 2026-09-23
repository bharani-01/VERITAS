from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

SPA_DIR = Path(__file__).parent / "static" / "spa"
SPA_INDEX = SPA_DIR / "index.html"
SPA_ASSETS = SPA_DIR / "assets"

LEGACY_STATIC = {
    "auth": Path(__file__).parent / "static" / "auth",
    "admin": Path(__file__).parent / "static" / "admin",
    "user": Path(__file__).parent / "static" / "user",
}

router = APIRouter(include_in_schema=False)


def spa_ready() -> bool:
    return SPA_INDEX.exists()


def mount_static(app: FastAPI) -> None:
    """Serve the React build (preferred) or legacy static trees before first build."""
    if spa_ready() and SPA_ASSETS.exists():
        app.mount("/assets", StaticFiles(directory=SPA_ASSETS), name="spa-assets")
        return
    auth_dir = LEGACY_STATIC["auth"]
    if auth_dir.exists():
        app.mount("/assets", StaticFiles(directory=auth_dir), name="assets")
    admin_dir = LEGACY_STATIC["admin"]
    if admin_dir.exists():
        app.mount("/admin/assets", StaticFiles(directory=admin_dir), name="admin-assets")
    user_dir = LEGACY_STATIC["user"]
    if user_dir.exists():
        app.mount("/user/assets", StaticFiles(directory=user_dir), name="user-assets")


def spa_or_legacy(page: str):
    if spa_ready():
        return FileResponse(SPA_INDEX)
    mapping = {
        "": LEGACY_STATIC["auth"] / "login.html",
        "signup": LEGACY_STATIC["auth"] / "signup.html",
        "forgot": LEGACY_STATIC["auth"] / "forgot.html",
        "reset": LEGACY_STATIC["auth"] / "reset.html",
        "verify": LEGACY_STATIC["auth"] / "verify.html",
        "admin": LEGACY_STATIC["admin"] / "index.html",
        "user": LEGACY_STATIC["user"] / "index.html",
    }
    target = mapping.get(page)
    if not target or not target.exists():
        raise HTTPException(
            status_code=503,
            detail="Frontend build missing. Run: cd frontend && npm run build",
        )
    return FileResponse(target)


@router.get("/")
def login_page():
    return spa_or_legacy("")


@router.get("/admin")
@router.get("/admin/")
@router.get("/admin/directory")
@router.get("/admin/audit")
@router.get("/admin/profile")
@router.get("/admin/settings")
def admin_spa():
    return spa_or_legacy("admin")


@router.get("/user")
@router.get("/user/")
@router.get("/user/profile")
@router.get("/user/settings")
@router.get("/user/projects")
@router.get("/user/projects/new")
@router.get("/user/scans")
@router.get("/user/integrations")
def user_spa():
    return spa_or_legacy("user")


@router.get("/user/projects/{project_id}")
@router.get("/user/projects/{project_id}/scans/{scan_id}")
def user_project_spa(project_id: str, scan_id: str | None = None):
    return spa_or_legacy("user")


@router.get("/report/{token}")
def shared_report_spa(token: str):
    return spa_or_legacy("")


@router.get("/signup")
def signup_page():
    return spa_or_legacy("signup")


@router.get("/forgot")
def forgot_page():
    return spa_or_legacy("forgot")


@router.get("/reset")
def reset_page():
    return spa_or_legacy("reset")


@router.get("/verify")
def verify_page():
    return spa_or_legacy("verify")


@router.get("/admin.html")
def admin_legacy_redirect():
    return RedirectResponse(url="/admin/", status_code=307)


@router.get("/profile.html")
def profile_legacy_redirect():
    return RedirectResponse(url="/user/", status_code=307)


@router.get("/{page}.html")
def html_legacy_redirect(page: str):
    if page == "admin":
        return RedirectResponse(url="/admin/", status_code=307)
    if page == "profile":
        return RedirectResponse(url="/user/", status_code=307)
    if page in {"signup", "forgot", "reset", "verify"}:
        return RedirectResponse(url=f"/{page}", status_code=307)
    if page in {"login", "index"}:
        return RedirectResponse(url="/", status_code=307)
    raise HTTPException(status_code=404, detail="Page not found.")
