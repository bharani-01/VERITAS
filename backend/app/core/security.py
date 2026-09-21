from __future__ import annotations

import hashlib
import re

from argon2 import PasswordHasher

password_hasher = PasswordHasher()

AVATAR_OPTIONS = ("slate", "forest", "ocean", "amber", "rose", "violet", "graphite", "mint")
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_email(value: str) -> str:
    return value.strip().lower()


def normalize_username(value: str) -> str:
    return value.strip().lower()
