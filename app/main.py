"""
FastAPI backend for the AI-Powered Multi-Layer Phishing Detection Platform.

Includes authentication, multi-layer analysis, AI Security Analyst chat,
CORS configuration, and strict security headers.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app import auth
from app.database import Base, SessionLocal, engine
from app.models import AnalysisResult, User
from app.routers import analyze as analyze_router
from app.routers import auth as auth_router
from app.routers import chat as chat_router

from src.analysis.analyze_artifact import analyze_artifact

# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------

Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------
# FASTAPI APPLICATION
# ---------------------------------------------------------

app = FastAPI(
    title="AI-Powered Multi-Layer Phishing Detection API",
    description=(
        "Multi-layer cybersecurity analysis platform "
        "for URLs, email, webpages and attachments."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------
# SECURITY HEADERS MIDDLEWARE
# ---------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ---------------------------------------------------------
# CORS CONFIGURATION
# ---------------------------------------------------------

ALLOWED_ORIGINS = [
    "http://localhost",
    "http://localhost:8000",
    "http://127.0.0.1",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# ---------------------------------------------------------
# ROUTERS
# ---------------------------------------------------------

# Authentication router
app.include_router(auth_router.router)

# Analysis router (primary /api/v1/analyze)
app.include_router(analyze_router.router)

# Analysis router alias (/api/v1/analysis) for frontend route compatibility
analysis_alias_router = analyze_router.router
app.include_router(analysis_alias_router, prefix="/api/v1/analysis")

# AI Security Analyst chat router
app.include_router(chat_router.router)


# ---------------------------------------------------------
# REQUEST MODEL
# ---------------------------------------------------------

class URLRequest(BaseModel):
    """Request model for legacy URL analysis endpoint."""
    url: HttpUrl = Field(..., description="HTTP or HTTPS URL to analyze.")


# ---------------------------------------------------------
# ROOT & HEALTH ENDPOINTS
# ---------------------------------------------------------

@app.get("/")
def root():
    """Return basic service metadata."""
    return {
        "service": "AI-Powered Multi-Layer Phishing Detection API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "url_analysis": "/api/v1/analyze/url",
            "chat": "/api/v1/chat",
            "documentation": "/docs",
        },
    }


@app.get("/health")
def health_check():
    """Health check probe."""
    return {
        "status": "healthy",
        "service": "phishing-detection-api",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------
# LEGACY COMPATIBILITY ENDPOINTS (Protected with User Isolation)
# ---------------------------------------------------------

@app.post("/analyze/url")
def legacy_analyze_url_endpoint(
    request: URLRequest,
    current_user: User = Depends(auth.get_current_user),
):
    """Legacy URL analysis endpoint protected by authentication."""
    url = str(request.url)
    try:
        result = analyze_artifact(url)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail={"message": "URL analysis failed.", "error": str(error)},
        )

    risk = result.get("risk", {})
    risk_score = risk.get("risk_score", 0)
    risk_level = risk.get("risk_level", "UNKNOWN")

    database_result = None
    db = SessionLocal()
    try:
        database_result = AnalysisResult(
            user_id=current_user.id,
            url=url,
            risk_score=float(risk_score),
            risk_level=str(risk_level),
            explanation=json.dumps(result.get("explanation", {})),
        )
        db.add(database_result)
        db.commit()
        db.refresh(database_result)
    except Exception as error:
        db.rollback()
        result["database_error"] = str(error)
    finally:
        db.close()

    result["analysis_id"] = database_result.id if database_result is not None else None
    return result


@app.get("/analysis/{analysis_id}")
def legacy_get_analysis(
    analysis_id: int,
    current_user: User = Depends(auth.get_current_user),
):
    """Retrieve a stored analysis with user IDOR verification."""
    db = SessionLocal()
    try:
        analysis_record = (
            db.query(AnalysisResult)
            .filter(AnalysisResult.id == analysis_id)
            .first()
        )
        if analysis_record is None:
            raise HTTPException(status_code=404, detail="Analysis not found.")

        # Multi-tenant IDOR defense
        if analysis_record.user_id is not None and analysis_record.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this analysis result.",
            )

        try:
            explanation = json.loads(analysis_record.explanation) if analysis_record.explanation else {}
        except Exception:
            explanation = {}

        return {
            "analysis_id": analysis_record.id,
            "url": analysis_record.url,
            "risk_score": analysis_record.risk_score,
            "risk_level": analysis_record.risk_level,
            "explanation": explanation,
            "created_at": analysis_record.created_at.isoformat() if analysis_record.created_at else None,
        }
    finally:
        db.close()


@app.get("/analysis")
def legacy_list_analyses(
    limit: int = 20,
    current_user: User = Depends(auth.get_current_user),
):
    """Return user-scoped recent analysis results."""
    limit = max(1, min(limit, 100))
    db = SessionLocal()
    try:
        analyses = (
            db.query(AnalysisResult)
            .filter(AnalysisResult.user_id == current_user.id)
            .order_by(AnalysisResult.created_at.desc())
            .limit(limit)
            .all()
        )
        results = [
            {
                "analysis_id": a.id,
                "url": a.url,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in analyses
        ]
        return {"count": len(results), "results": results}
    finally:
        db.close()
