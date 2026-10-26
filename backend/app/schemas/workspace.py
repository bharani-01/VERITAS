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
    scan_options: dict | None = None
    sla_critical_days: int | None = None
    sla_high_days: int | None = None
    sla_medium_days: int | None = None
    sla_low_days: int | None = None
    require_suppression_approval: bool | None = None


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


class FindingStatusPatch(BaseModel):
    status: str = "false_positive"
    suppress: bool = False
    reason: str | None = Field(default=None, max_length=512)
    suppression_type: str = Field(
        default="false_positive",
        pattern="^(false_positive|risk_accepted|compensating_control)$",
    )
    justification: str | None = Field(default=None, max_length=2000)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    request_approval: bool = False


class ProjectMemberIn(BaseModel):
    email: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=128)
    user_id: str | None = Field(default=None, max_length=64)
    role: str = Field(pattern="^(security_lead|developer|auditor)$")


class SuppressionReviewIn(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    review_note: str | None = Field(default=None, max_length=512)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class GitHubLinkRepoIn(BaseModel):
    github_repo_id: int

