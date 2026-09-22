from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_secret
from app.models import GitHubConnection, Project, User
from app.services import github as github_svc


class CloneError(RuntimeError):
    pass


def _git_bin() -> str:
    found = shutil.which("git")
    if found:
        return found
    for candidate in ("/usr/bin/git", "/bin/git", "/usr/local/bin/git"):
        if Path(candidate).is_file():
            return candidate
    raise CloneError("git is not installed on the scan host (apt install git).")


def prepare_workdir(scan_id: str) -> Path:
    root = Path(tempfile.gettempdir()) / "veritas-scans" / scan_id
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _force_writable(path: Path) -> None:
    """Make cloned trees deletable (git often leaves read-only files)."""
    if not path.exists():
        return
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            target = Path(root) / name
            try:
                os.chmod(target, 0o700 if target.is_dir() else 0o600)
            except OSError:
                pass
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def cleanup_workdir(path: Path | None) -> None:
    """Delete the scan workspace (cloned repo + temp files) after the scan finishes."""
    if not path:
        return
    target = Path(path)
    if not target.exists():
        return
    _force_writable(target)
    shutil.rmtree(target, ignore_errors=True)
    if target.exists():
        # Last resort: delete nested repo first, then parent.
        repo = target / "repo"
        if repo.exists():
            _force_writable(repo)
            shutil.rmtree(repo, ignore_errors=True)
        _force_writable(target)
        shutil.rmtree(target, ignore_errors=True)


def purge_all_scan_workdirs() -> None:
    """Remove every leftover /tmp/veritas-scans/* directory (orphans after crashes)."""
    root = Path(tempfile.gettempdir()) / "veritas-scans"
    if not root.is_dir():
        return
    for child in root.iterdir():
        cleanup_workdir(child)


def read_git_version(repo_path: Path) -> dict:
    """Capture HEAD commit identity and a short recent history (version trail)."""
    git = _git_bin()
    meta: dict = {"commit_sha": None, "commit_short": None, "commit_message": None, "commit_author": None, "history": []}
    try:
        sha = subprocess.run(
            [git, "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if sha.returncode == 0:
            full = (sha.stdout or "").strip()
            meta["commit_sha"] = full
            meta["commit_short"] = full[:7] if full else None
        subject = subprocess.run(
            [git, "-C", str(repo_path), "log", "-1", "--pretty=format:%s"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if subject.returncode == 0:
            meta["commit_message"] = (subject.stdout or "").strip()[:512] or None
        author = subprocess.run(
            [git, "-C", str(repo_path), "log", "-1", "--pretty=format:%an <%ae>"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if author.returncode == 0:
            meta["commit_author"] = (author.stdout or "").strip()[:256] or None
        hist = subprocess.run(
            [git, "-C", str(repo_path), "log", "-n", "8", "--pretty=format:%H|%h|%s|%an|%ci"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if hist.returncode == 0:
            rows = []
            for line in (hist.stdout or "").splitlines():
                parts = line.split("|", 4)
                if len(parts) == 5:
                    rows.append(
                        {
                            "sha": parts[0],
                            "short": parts[1],
                            "message": parts[2][:200],
                            "author": parts[3][:120],
                            "date": parts[4],
                        }
                    )
            meta["history"] = rows
    except Exception:
        pass
    return meta


def clone_project_repo(db: Session, user: User, project: Project, workdir: Path, ref: str | None = None) -> tuple[str, dict]:
    if not project.github_repo_full_name or project.github_repo_id is None:
        raise CloneError("Project has no linked GitHub repository.")
    try:
        github_svc.verify_owned_repo(db, user, int(project.github_repo_id))
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else "GitHub authorization failed."
        raise CloneError(detail) from exc
    conn = db.scalar(
        select(GitHubConnection).where(GitHubConnection.user_id == user.id, GitHubConnection.revoked_at.is_(None))
    )
    if not conn:
        raise CloneError("Connect GitHub before scanning a linked repository.")
    token = decrypt_secret(conn.token_encrypted)
    branch = ref or project.github_default_branch or "main"
    url = f"https://x-access-token:{token}@github.com/{project.github_repo_full_name}.git"
    dest = workdir / "repo"
    git = _git_bin()
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "echo",
    }
    # Depth > 1 so the report can show a short version history trail.
    proc = subprocess.run(
        [git, "clone", "--depth", "12", "--single-branch", "--branch", branch, url, str(dest)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        proc = subprocess.run(
            [git, "clone", "--depth", "12", "--single-branch", url, str(dest)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env=env,
        )
    if proc.returncode != 0 or not dest.exists():
        err = (proc.stderr or proc.stdout or "git clone failed")[:400].replace(token, "***")
        raise CloneError(err)
    return str(dest), read_git_version(dest)
