from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import (
    github_client_id,
    github_client_secret,
    github_env_file_found,
    github_redirect_uri,
)
from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.time import utcnow
from app.models import GitHubConnection, User

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"

# Ephemeral OAuth state (process-local). Fine for single-process Phase 2; replace with Redis later if needed.
_oauth_states: dict[str, str] = {}


def github_configured() -> bool:
    return bool(github_client_id() and github_client_secret() and github_redirect_uri())


def github_config_report() -> dict:
    """Presence-only report (never returns secret values)."""
    missing: list[str] = []
    if not github_client_id():
        missing.append("GITHUB_CLIENT_ID")
    if not github_client_secret():
        missing.append("GITHUB_CLIENT_SECRET")
    if not github_redirect_uri():
        missing.append("GITHUB_REDIRECT_URI")
    return {
        "configured": not missing,
        "missing": missing,
        "env_file_found": github_env_file_found(),
    }


def require_github_configured() -> None:
    if not github_configured():
        raise HTTPException(status_code=503, detail="GitHub integration is not configured on this server.")


def active_connection(db: Session, user: User) -> GitHubConnection | None:
    conn = db.scalar(
        select(GitHubConnection).where(
            GitHubConnection.user_id == user.id,
            GitHubConnection.revoked_at.is_(None),
        )
    )
    return conn


def connection_status(db: Session, user: User) -> dict:
    report = github_config_report()
    conn = active_connection(db, user)
    return {
        "configured": report["configured"],
        "missing": report["missing"],
        "env_file_found": report["env_file_found"],
        "connected": bool(conn),
        "github_login": conn.github_login if conn else None,
        "avatar_url": conn.avatar_url if conn else None,
        "connected_at": conn.connected_at if conn else None,
    }


def begin_oauth(user: User) -> str:
    require_github_configured()
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = user.id
    params = {
        "client_id": github_client_id(),
        "redirect_uri": github_redirect_uri(),
        "scope": "read:user repo",
        "state": state,
        "allow_signup": "false",
    }
    return f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"


def _consume_state(state: str) -> str:
    user_id = _oauth_states.pop(state, None)
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state.")
    return user_id


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VERITAS-Infosec",
    }


def complete_oauth(db: Session, *, code: str, state: str) -> GitHubConnection:
    require_github_configured()
    user_id = _consume_state(state)
    with httpx.Client(timeout=20.0) as client:
        token_resp = client.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": github_client_id(),
                "client_secret": github_client_secret(),
                "code": code,
                "redirect_uri": github_redirect_uri(),
            },
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="GitHub did not return an access token.")
        scopes = token_data.get("scope") or ""
        user_resp = client.get(f"{GITHUB_API}/user", headers=_github_headers(access_token))
        user_resp.raise_for_status()
        gh_user = user_resp.json()

    existing = db.scalar(select(GitHubConnection).where(GitHubConnection.user_id == user_id))
    if existing:
        existing.github_user_id = int(gh_user["id"])
        existing.github_login = gh_user["login"]
        existing.avatar_url = gh_user.get("avatar_url")
        existing.token_encrypted = encrypt_secret(access_token)
        existing.scopes = scopes
        existing.connected_at = utcnow()
        existing.revoked_at = None
        conn = existing
    else:
        conn = GitHubConnection(
            user_id=user_id,
            github_user_id=int(gh_user["id"]),
            github_login=gh_user["login"],
            avatar_url=gh_user.get("avatar_url"),
            token_encrypted=encrypt_secret(access_token),
            scopes=scopes,
        )
        db.add(conn)
    db.commit()
    db.refresh(conn)
    return conn


def disconnect(db: Session, user: User) -> None:
    conn = active_connection(db, user)
    if not conn:
        return
    conn.revoked_at = utcnow()
    conn.token_encrypted = encrypt_secret(secrets.token_urlsafe(16))
    db.add(conn)
    db.commit()


def _access_token(db: Session, user: User) -> tuple[GitHubConnection, str]:
    conn = active_connection(db, user)
    if not conn:
        raise HTTPException(status_code=400, detail="Connect GitHub before listing repositories.")
    try:
        token = decrypt_secret(conn.token_encrypted)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="GitHub connection is invalid. Reconnect GitHub.") from exc
    return conn, token


def list_owned_repos(db: Session, user: User, *, page: int = 1, per_page: int = 30) -> list[dict[str, Any]]:
    conn, token = _access_token(db, user)
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    with httpx.Client(timeout=20.0) as client:
        resp = client.get(
            f"{GITHUB_API}/user/repos",
            headers=_github_headers(token),
            params={
                "affiliation": "owner",
                "visibility": "all",
                "sort": "updated",
                "per_page": per_page,
                "page": page,
            },
        )
        if resp.status_code == 401:
            raise HTTPException(status_code=400, detail="GitHub authorization expired. Reconnect GitHub.")
        resp.raise_for_status()
        repos = resp.json()

    owned: list[dict[str, Any]] = []
    for repo in repos:
        owner = repo.get("owner") or {}
        if int(owner.get("id") or 0) != conn.github_user_id:
            continue
        if (owner.get("login") or "").lower() != conn.github_login.lower():
            continue
        owned.append(
            {
                "id": repo["id"],
                "full_name": repo["full_name"],
                "name": repo["name"],
                "private": repo.get("private", False),
                "default_branch": repo.get("default_branch"),
                "html_url": repo.get("html_url"),
                "description": repo.get("description") or "",
            }
        )
    return owned


def verify_owned_repo(db: Session, user: User, github_repo_id: int) -> dict[str, Any]:
    """Server-side re-check: fetch repo by id and require owner == connected GitHub user."""
    conn, token = _access_token(db, user)
    with httpx.Client(timeout=20.0) as client:
        resp = client.get(f"{GITHUB_API}/repositories/{int(github_repo_id)}", headers=_github_headers(token))
        if resp.status_code == 404:
            raise HTTPException(status_code=400, detail="Repository not found or not accessible.")
        if resp.status_code == 401:
            raise HTTPException(status_code=400, detail="GitHub authorization expired. Reconnect GitHub.")
        resp.raise_for_status()
        repo = resp.json()

    owner = repo.get("owner") or {}
    owner_id = int(owner.get("id") or 0)
    owner_login = (owner.get("login") or "").lower()
    if owner_id != conn.github_user_id or owner_login != conn.github_login.lower():
        raise HTTPException(
            status_code=400,
            detail="Only repositories owned by your connected GitHub account can be linked.",
        )
    return {
        "id": repo["id"],
        "full_name": repo["full_name"],
        "name": repo.get("name"),
        "private": repo.get("private", False),
        "default_branch": repo.get("default_branch"),
        "html_url": repo.get("html_url"),
        "description": repo.get("description") or "",
    }
