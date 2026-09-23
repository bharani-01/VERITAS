from __future__ import annotations

import os
from pathlib import Path


_ENV_CANDIDATES = [
    Path(__file__).resolve().parents[2] / ".env",  # backend/.env
    Path.cwd() / "backend" / ".env",
    Path.cwd() / ".env",
]


def _env_path() -> Path:
    for path in _ENV_CANDIDATES:
        if path.is_file():
            return path
    return _ENV_CANDIDATES[0]


_ENV_PATH = _env_path()


def _parse_env_file(path: Path) -> dict[str, str]:
    """Minimal .env parser (ASCII/UTF-8). Does not depend on python-dotenv quirks."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    text = path.read_text(encoding="utf-8-sig")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def reload_env() -> Path:
    """Load backend/.env into os.environ without clobbering already-set process vars.

    Process environment (including test setup) wins over the file so local/tests
    can override bootstrap credentials safely.
    """
    global _ENV_PATH
    path = _env_path()
    _ENV_PATH = path
    for key, value in _parse_env_file(path).items():
        os.environ.setdefault(key, value)
    try:
        from dotenv import load_dotenv

        if path.is_file():
            load_dotenv(path, override=False, encoding="utf-8-sig")
    except Exception:
        pass
    return path


reload_env()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./veritas.db")
APP_ENV = os.getenv("APP_ENV", "development").lower()
COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true" if APP_ENV == "production" else "false").lower() == "true"
PUBLIC_APP_URL = os.getenv("PUBLIC_APP_URL", "http://localhost:8000").rstrip("/")
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "24"))
BOOTSTRAP = {
    "email": os.getenv("VERITAS_BOOTSTRAP_ADMIN_EMAIL", ""),
    "password": os.getenv("VERITAS_BOOTSTRAP_ADMIN_PASSWORD", ""),
    "name": os.getenv("VERITAS_BOOTSTRAP_ADMIN_NAME", ""),
}
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "VERITAS <onboarding@resend.dev>")

TOKEN_ENCRYPTION_SECRET = os.getenv("TOKEN_ENCRYPTION_SECRET", "") or os.getenv(
    "VERITAS_BOOTSTRAP_ADMIN_PASSWORD", "veritas-dev-token-secret-change-me"
)

# Optional Phase 3 AI triage (Groq OpenAI-compatible API). Fail-open when unset.
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "") or os.getenv("AI_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Phase 4 scan quotas (per user)
SCAN_RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "10"))
SCAN_RATE_WINDOW_SECONDS = int(os.getenv("SCAN_RATE_WINDOW_SECONDS", "3600"))
SCAN_CONCURRENT_LIMIT = int(os.getenv("SCAN_CONCURRENT_LIMIT", "2"))


def github_client_id() -> str:
    reload_env()
    return (os.getenv("GITHUB_CLIENT_ID") or "").strip()


def github_client_secret() -> str:
    reload_env()
    return (os.getenv("GITHUB_CLIENT_SECRET") or "").strip()


def github_redirect_uri() -> str:
    reload_env()
    explicit = (os.getenv("GITHUB_REDIRECT_URI") or "").strip()
    if explicit:
        return explicit
    public = (os.getenv("PUBLIC_APP_URL") or "http://localhost:8000").rstrip("/")
    return f"{public}/workspace/github/callback"


def github_env_file_found() -> bool:
    return _env_path().is_file()


# Back-compat aliases
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "") or ""
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "") or ""
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "") or github_redirect_uri()
