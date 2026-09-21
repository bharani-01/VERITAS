from __future__ import annotations

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    github_repo_id: int | None = None


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    github_repo_id: int | None = None
    clear_github: bool = False


class ScanCreate(BaseModel):
    target: str | None = Field(default=None, min_length=1, max_length=512)
