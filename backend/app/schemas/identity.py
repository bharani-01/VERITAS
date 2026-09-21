from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class SignupInput(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)


class LoginInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenInput(BaseModel):
    token: str = Field(min_length=20, max_length=512)


class EmailInput(BaseModel):
    email: EmailStr


class ResetInput(TokenInput):
    password: str = Field(min_length=12, max_length=256)


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    email: EmailStr | None = None
    role: Literal["admin", "user"] | None = None


class ProfileUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    username: str | None = Field(default=None, min_length=3, max_length=32)
    avatar: str | None = Field(default=None, min_length=2, max_length=32)
