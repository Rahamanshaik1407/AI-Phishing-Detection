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

# -------------------------------------------------------------------
# ANALYSIS SCHEMAS
# -------------------------------------------------------------------

from pydantic import HttpUrl, BaseModel, Field
from typing import List, Optional, Dict, Any

class URLInput(BaseModel):
    """Request payload for URL analysis."""
    url: HttpUrl = Field(..., description="HTTP or HTTPS URL to analyze")

class HashInput(BaseModel):
    """Request payload for hash analysis."""
    hash: str = Field(
        ..., min_length=32, max_length=64, description="MD5/SHA1/SHA256 hash string"
    )

class AnalysisResponse(BaseModel):
    """Unified response format for all analysis endpoints."""
    analysis_id: Optional[int] = None
    artifact_type: str
    risk: Dict[str, Any]
    summary: str = ""
    signals: List[Any] = []
    details: Dict[str, Any] = {}
    explanation: Dict[str, Any] = {}
    errors: List[str] = []

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------------
# CHAT / AI SECURITY ANALYST SCHEMAS
# -------------------------------------------------------------------

class ChatRequest(BaseModel):
    """Payload for AI Security Analyst chat queries."""
    message: str = Field(..., min_length=1, max_length=2000, description="User question or analysis inquiry")
    analysis_id: Optional[int] = Field(None, description="Optional ID of saved analysis to load context from")
    analysis_context: Optional[Dict[str, Any]] = Field(None, description="Optional direct analysis result dictionary")


class ChatResponse(BaseModel):
    """Response format for AI Security Analyst chat."""
    response: str
    artifact_type: Optional[str] = None
    risk_level: Optional[str] = None
    provider: str = "security_analyst"
    timestamp: str

    model_config = ConfigDict(from_attributes=True)

