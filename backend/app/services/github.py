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
        "needs_reauth": bool(conn.needs_reauth) if conn else False,
        "github_login": conn.github_login if conn else None,
        "avatar_url": conn.avatar_url if conn else None,
        "scopes": conn.scopes if conn else None,
        "connected_at": conn.connected_at if conn else None,
    }


def mark_needs_reauth(db: Session, conn: GitHubConnection | None) -> None:
    if not conn:
        return
    conn.needs_reauth = True
    db.add(conn)
    db.commit()


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
        existing.needs_reauth = False
        conn = existing
    else:
        conn = GitHubConnection(
            user_id=user_id,
            github_user_id=int(gh_user["id"]),
            github_login=gh_user["login"],
            avatar_url=gh_user.get("avatar_url"),
            token_encrypted=encrypt_secret(access_token),
            scopes=scopes,
            needs_reauth=False,
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


def _raise_github_auth(db: Session, conn: GitHubConnection) -> None:
    mark_needs_reauth(db, conn)
    raise HTTPException(status_code=400, detail="GitHub authorization expired. Reconnect GitHub.")


def _raise_github_forbidden() -> None:
    """403 is often rate-limit / temporary — do not mark needs_reauth."""
    raise HTTPException(
        status_code=429,
        detail="GitHub temporarily denied this request (rate limit or access). Try again shortly.",
    )


def _note_github_ok(db: Session, conn: GitHubConnection) -> None:
    if conn.needs_reauth:
        conn.needs_reauth = False
        db.add(conn)
        db.commit()


def _handle_github_http(db: Session, conn: GitHubConnection, resp: httpx.Response) -> None:
    if resp.status_code == 401:
        _raise_github_auth(db, conn)
    if resp.status_code == 403:
        _raise_github_forbidden()


def _access_token(db: Session, user: User) -> tuple[GitHubConnection, str]:
    conn = active_connection(db, user)
    if not conn:
        raise HTTPException(status_code=400, detail="Connect GitHub before listing repositories.")
    # Do not hard-block on needs_reauth: false positives (403) used to set the flag.
    # Real failures still re-set it on HTTP 401.
    try:
        token = decrypt_secret(conn.token_encrypted)
    except ValueError as exc:
        mark_needs_reauth(db, conn)
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
            _raise_github_auth(db, conn)
        if resp.status_code == 403:
            _raise_github_forbidden()
        resp.raise_for_status()
        repos = resp.json()
    _note_github_ok(db, conn)

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
                "updated_at": repo.get("pushed_at") or repo.get("updated_at"),
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
            _raise_github_auth(db, conn)
        if resp.status_code == 403:
            _raise_github_forbidden()
        resp.raise_for_status()
        repo = resp.json()
    _note_github_ok(db, conn)

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


def list_repo_refs(db: Session, user: User, full_name: str) -> dict[str, Any]:
    """List branches and tags for owner/repo (capped)."""
    conn, token = _access_token(db, user)
    owner_repo = (full_name or "").strip()
    if "/" not in owner_repo:
        raise HTTPException(status_code=400, detail="Invalid repository name.")
    branches: list[dict[str, str]] = []
    tags: list[dict[str, str]] = []
    with httpx.Client(timeout=20.0) as client:
        for kind, dest in (("branches", branches), ("tags", tags)):
            page = 1
            while page <= 3 and len(dest) < 100:
                resp = client.get(
                    f"{GITHUB_API}/repos/{owner_repo}/{kind}",
                    headers=_github_headers(token),
                    params={"per_page": 100, "page": page},
                )
                if resp.status_code == 401:
                    _raise_github_auth(db, conn)
                if resp.status_code == 403:
                    _raise_github_forbidden()
                if resp.status_code == 404:
                    raise HTTPException(status_code=400, detail="Repository not found or not accessible.")
                resp.raise_for_status()
                rows = resp.json() or []
                if not rows:
                    break
                for row in rows:
                    name = row.get("name")
                    if name:
                        dest.append({"name": name, "type": "branch" if kind == "branches" else "tag"})
                if len(rows) < 100:
                    break
                page += 1
    _note_github_ok(db, conn)
    return {"branches": branches[:100], "tags": tags[:100], "default": None}


def create_repo_push_webhook(
    db: Session,
    user: User,
    *,
    full_name: str,
    secret: str,
    webhook_url: str,
) -> int:
    """Create a GitHub push webhook; returns hook id."""
    conn, token = _access_token(db, user)
    owner_repo = (full_name or "").strip()
    if "/" not in owner_repo:
        raise HTTPException(status_code=400, detail="Invalid repository name.")
    payload = {
        "name": "web",
        "active": True,
        "events": ["push"],
        "config": {
            "url": webhook_url,
            "content_type": "json",
            "secret": secret,
            "insecure_ssl": "0",
        },
    }
    with httpx.Client(timeout=20.0) as client:
        resp = client.post(
            f"{GITHUB_API}/repos/{owner_repo}/hooks",
            headers=_github_headers(token),
            json=payload,
        )
        if resp.status_code == 401:
            _raise_github_auth(db, conn)
        if resp.status_code == 403:
            _raise_github_forbidden()
        if resp.status_code == 422:
            # Hook may already exist for this URL — try to find and reuse.
            listed = client.get(
                f"{GITHUB_API}/repos/{owner_repo}/hooks",
                headers=_github_headers(token),
                params={"per_page": 100},
            )
            if listed.status_code == 200:
                for hook in listed.json() or []:
                    cfg = hook.get("config") or {}
                    if (cfg.get("url") or "").rstrip("/") == webhook_url.rstrip("/"):
                        # Update secret/events
                        patch = client.patch(
                            f"{GITHUB_API}/repos/{owner_repo}/hooks/{hook['id']}",
                            headers=_github_headers(token),
                            json=payload,
                        )
                        if patch.status_code < 300:
                            _note_github_ok(db, conn)
                            return int(hook["id"])
            raise HTTPException(status_code=400, detail="Could not create GitHub webhook (validation failed).")
        resp.raise_for_status()
        data = resp.json()
    _note_github_ok(db, conn)
    return int(data["id"])


def delete_repo_webhook(
    db: Session,
    user: User,
    *,
    full_name: str,
    hook_id: int,
) -> None:
    conn, token = _access_token(db, user)
    owner_repo = (full_name or "").strip()
    if "/" not in owner_repo or not hook_id:
        return
    with httpx.Client(timeout=20.0) as client:
        resp = client.delete(
            f"{GITHUB_API}/repos/{owner_repo}/hooks/{int(hook_id)}",
            headers=_github_headers(token),
        )
        if resp.status_code == 401:
            _raise_github_auth(db, conn)
        if resp.status_code in {404, 204}:
            _note_github_ok(db, conn)
            return
        if resp.status_code == 403:
            # Best-effort delete; don't flip reauth for temporary 403
            return
        if resp.status_code >= 400:
            return
    _note_github_ok(db, conn)

