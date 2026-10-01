"""
Application configuration management.

Loads settings from environment variables with safe development defaults.
Enforces strict secret validation for production environments.
"""

import os
from datetime import timedelta

# Environment mode: 'development', 'testing', or 'production'
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishing_analysis.db")

# Security / JWT settings
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Secret key resolution
_SECRET_KEY = os.getenv("SECRET_KEY")

if not _SECRET_KEY:
    if ENVIRONMENT == "production":
        raise ValueError(
            "CRITICAL CONFIGURATION ERROR: 'SECRET_KEY' environment variable "
            "must be explicitly set in production mode."
        )
    # Safe development default (never used in production)
    _SECRET_KEY = "phishguard-dev-only-secret-key-not-for-production-use"

SECRET_KEY = _SECRET_KEY
