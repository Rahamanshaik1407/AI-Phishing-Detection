"""
Pydantic schemas for request validation and response formatting.

Guarantees that sensitive data (passwords, hashes, secret keys)
are never exposed through API responses.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import EmailStr
from pydantic import Field


# -------------------------------------------------------------------
# AUTHENTICATION SCHEMAS
# -------------------------------------------------------------------

class UserRegister(BaseModel):
    """
    User registration payload.
    """
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Alphanumeric username (allowed: letters, numbers, _, -, .)"
    )
    email: EmailStr = Field(
        ...,
        description="Valid email address"
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Account password (min 8 characters)"
    )


class UserLogin(BaseModel):
    """
    User login payload. Supports logging in with either username or email.
    """
    email_or_username: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Registered email address or username"
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Account password"
    )


class UserResponse(BaseModel):
    """
    Safe public user information (no password hash).
    """
    id: int
    username: str
    email: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """
    JWT authentication response payload.
    """
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class PasswordChange(BaseModel):
    """
    Password change request payload.
    """
    current_password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Current account password"
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New account password (min 8 characters)"
    )
