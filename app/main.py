"""
FastAPI backend for the AI-Powered Multi-Layer Phishing Detection Platform.

Integrates authentication router for user management.
"""

import json
from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, HttpUrl

from app.database import Base, SessionLocal, engine
from app.models import AnalysisResult
from app.routers import auth as auth_router

from src.analysis.analyze_artifact import analyze_artifact

# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------

# Create database tables if they do not already exist.
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

# Include authentication router
app.include_router(auth_router.router)

# ---------------------------------------------------------
# REQUEST MODEL
# ---------------------------------------------------------

class URLRequest(BaseModel):
    """Request model for URL analysis.

    HttpUrl performs basic validation and only accepts
    valid HTTP/HTTPS URLs.
    """

    url: HttpUrl = Field(
        ..., description="HTTP or HTTPS URL to analyze."
    )

# ---------------------------------------------------------
# ROOT ENDPOINT
# ---------------------------------------------------------

@app.get("/")
def root():
    """Return basic information about the API."""
    return {
        "service": (
            "AI-Powered Multi-Layer "
            "Phishing Detection API"
        ),
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "url_analysis": "/analyze/url",
            "documentation": "/docs",
        },
    }

# ---------------------------------------------------------
# HEALTH ENDPOINT
# ---------------------------------------------------------

@app.get("/health")
def health_check():
    """Check whether the API is running."""
    return {
        "status": "healthy",
        "service": "phishing-detection-api",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

# ---------------------------------------------------------
# URL ANALYSIS
# ---------------------------------------------------------

@app.post("/analyze/url")
def analyze_url_endpoint(request: URLRequest):
    """Analyze a URL through the complete security pipeline.

    Pipeline:
        URL -> features -> risk engine -> explanation -> database
    """
    url = str(request.url)

    # Run analysis
    try:
        result = analyze_artifact(url)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail={"message": "URL analysis failed.", "error": str(error)},
        )

    # Extract risk information
    risk = result.get("risk", {})
    risk_score = risk.get("risk_score", 0)
    risk_level = risk.get("risk_level", "UNKNOWN")

    # Save result
    database_result = None
    db = SessionLocal()
    try:
        database_result = AnalysisResult(
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

    if database_result is not None:
        result["analysis_id"] = database_result.id
    else:
        result["analysis_id"] = None
    return result

# ---------------------------------------------------------
# GET ONE ANALYSIS
# ---------------------------------------------------------

@app.get("/analysis/{analysis_id}")
def get_analysis(analysis_id: int):
    """Retrieve a previously stored analysis."""
    db = SessionLocal()
    try:
        analysis = (
            db.query(AnalysisResult)
            .filter(AnalysisResult.id == analysis_id)
            .first()
        )
        if analysis is None:
            raise HTTPException(status_code=404, detail="Analysis not found.")
        try:
            explanation = json.loads(analysis.explanation)
        except (TypeError, json.JSONDecodeError):
            explanation = {}
        return {
            "analysis_id": analysis.id,
            "url": analysis.url,
            "risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level,
            "explanation": explanation,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        }
    finally:
        db.close()

# ---------------------------------------------------------
# GET ANALYSIS HISTORY
# ---------------------------------------------------------

@app.get("/analysis")
def list_analyses(limit: int = 20):
    """Return recent analysis results.

    Maximum number of results is limited to 100.
    """
    limit = max(1, min(limit, 100))
    db = SessionLocal()
    try:
        analyses = (
            db.query(AnalysisResult)
            .order_by(AnalysisResult.created_at.desc())
            .limit(limit)
            .all()
        )
        results = []
        for analysis in analyses:
            results.append(
                {
                    "analysis_id": analysis.id,
                    "url": analysis.url,
                    "risk_score": analysis.risk_score,
                    "risk_level": analysis.risk_level,
                    "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
                }
            )
        return {"count": len(results), "results": results}
    finally:
        db.close()
