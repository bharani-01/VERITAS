from __future__ import annotations

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    github_repo_id: int | None = None
    security_level: str = "standard"
    auto_scan_on_push: bool = False
    auto_scan_branch: str | None = Field(default=None, max_length=128)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    github_repo_id: int | None = None
    clear_github: bool = False
    security_level: str | None = None
    base_url: str | None = Field(default=None, max_length=512)
    criticality: str | None = None
    notify_email_default: bool | None = None
    notify_in_app_default: bool | None = None
    auto_scan_on_push: bool | None = None
    auto_scan_branch: str | None = Field(default=None, max_length=128)


class ScanCreate(BaseModel):
    target: str | None = Field(default=None, min_length=1, max_length=512)
    security_level: str | None = None
    scan_mode: str | None = None
    scan_scope: str | None = None
    notify_email: bool | None = None
    notify_in_app: bool | None = None
    ref: str | None = Field(default=None, max_length=128)
    engines: list[str] | None = None
    path_excludes: list[str] | None = None
    fail_severity: str | None = None  # off | critical | high | medium
    code_review: bool | None = None  # OpenRouter review when Rules+AI


class FindingStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=16)


class FindingSuppressCreate(BaseModel):
    reason: str | None = Field(default=None, max_length=512)
