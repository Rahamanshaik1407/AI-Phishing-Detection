"""
app/routers/chat.py

Protected API endpoints for the AI Security Analyst chat assistant.
Requires authentication and provides multi-tenant access controls on analysis contexts.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import auth, database, models, schemas
from src.analysis.security_chat import process_chat_message

router = APIRouter(prefix="/api/v1/chat", tags=["chat"])

MAX_CONTEXT_SIZE_BYTES = 200_000  # 200 KB limit for inline context payloads


@router.post("", response_model=schemas.ChatResponse)
def security_analyst_chat_endpoint(
    payload: schemas.ChatRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Protected chat endpoint for the PHISHGUARD AI Security Analyst.

    Allows an authenticated security analyst to query findings, risk breakdowns,
    and investigation guidance for a specific analysis result.
    """
    message = payload.message.strip()
    if not message:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message cannot be empty or whitespace only.",
        )

    if len(message) > 2000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message exceeds maximum allowed length of 2000 characters.",
        )

    context: Dict[str, Any] = {}

    # 1. Load context from database if analysis_id is provided
    if payload.analysis_id is not None:
        analysis_record = (
            db.query(models.AnalysisResult)
            .filter(models.AnalysisResult.id == payload.analysis_id)
            .first()
        )
        if analysis_record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis with ID {payload.analysis_id} not found.",
            )

        # Enforce multi-tenant access control: user can only chat about their own analyses
        if analysis_record.user_id is not None and analysis_record.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access another user's analysis context.",
            )

        # Parse stored record details
        try:
            stored_details = json.loads(analysis_record.details) if analysis_record.details else {}
        except Exception:
            stored_details = {}

        try:
            stored_explanation = json.loads(analysis_record.explanation) if analysis_record.explanation else {}
        except Exception:
            stored_explanation = {}

        context = {
            "analysis_id": analysis_record.id,
            "artifact_type": analysis_record.artifact_type,
            "url": analysis_record.url,
            "risk_score": analysis_record.risk_score,
            "risk_level": analysis_record.risk_level,
            "details": stored_details,
            "explanation": stored_explanation,
            "summary": stored_explanation.get("summary", ""),
        }

    # 2. Merge/use direct analysis_context if supplied
    if payload.analysis_context:
        try:
            serialized = json.dumps(payload.analysis_context)
            if len(serialized) > MAX_CONTEXT_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Analysis context payload exceeds maximum allowed size.",
                )
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON structure in analysis context.",
            )

        # If both are provided, update base context with any fresh fields
        if context:
            context.update(payload.analysis_context)
        else:
            context = payload.analysis_context

    # 3. Process chat message through security analyst engine
    try:
        chat_result = process_chat_message(
            user_message=message,
            analysis_context=context,
        )
        return chat_result
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security analyst failed to process query: {str(exc)}",
        )
