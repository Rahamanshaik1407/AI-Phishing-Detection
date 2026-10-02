import uuid
import json
import os
import hashlib
from typing import List, Dict, Any

from src.features.url_analyzer import analyze_url as url_analyzer
from src.features.reputation import get_hash_reputation
from src.features.email_analyzer import analyze_email as email_analyzer
from src.features.qr_analyzer import analyze_qr_code as qr_analyzer
from src.features.attachment_analyzer import analyze_attachment as attachment_analyzer
from src.features.attachment_url_extractor import extract_urls_from_attachment as attachment_url_extractor

from src.analysis.risk_engine import analyze_url_risk
from src.analysis.explanation_engine import generate_explanation
from src.analysis.evidence_correlator import correlate_evidence
from src.analysis.model_explainer import explain_url_model
from src.analysis.multi_layer_risk import aggregate_multi_layer_risk
# Helper to compute SHA256 of a file
def _sha256_file(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# Standard response builder
def _build_response(
    analysis_id: Any,
    artifact_type: str,
    details: Dict[str, Any],
    risk_result: Any,
    explanation: Dict[str, Any],
    errors: List[str] = None,
) -> Dict[str, Any]:
    if errors is None:
        errors = []
    return {
        "analysis_id": analysis_id,
        "artifact_type": artifact_type,
        "risk": {
            "score": getattr(risk_result, "score", 0),
            "level": getattr(risk_result, "level", "UNKNOWN"),
        },
        "summary": explanation.get("summary", ""),
        "signals": getattr(risk_result, "signals", []),
        "details": details,
        "explanation": explanation,
        "errors": errors,
    }

def analyze_url(url: str, user_id: int) -> Dict[str, Any]:
    """Analyze a URL using deterministic logic and optional ML inference.

    The deterministic pipeline populates ``url_details`` and risk information.
    Afterwards we attempt to run the lightweight ML model (if the artifact is
    present).  The ML result is attached under the top‑level ``ml`` key in the
    response; if the model is unavailable, the field indicates so.
    """
    errors = []
    # Deterministic analysis.
    try:
        url_details = url_analyzer(url)
    except Exception as exc:
        url_details = {}
        errors.append(str(exc))
    risk_res = analyze_url_risk(url_details)
    explanation = generate_explanation(risk_res)

    # ML inference – graceful fallback when the model file or joblib is missing.
    try:
        from src.models.url_model_inference import predict_url
        ml_result = predict_url(url)
    except Exception:
        ml_result = {"model_available": False, "probability": None, "features": {}}

    # Build the deterministic response first.
    response = _build_response(
        analysis_id=None,
        artifact_type="url",
        details=url_details,
        risk_result=risk_res,
        explanation=explanation,
        errors=errors,
    )
    # Attach ML information.
    response["ml"] = ml_result
    # Phase 8B: Model explanation for URL ML model.
    try:
        response["model_explanation"] = explain_url_model(url)
    except Exception:
        response["model_explanation"] = None

    # Phase 8A: Evidence correlation — consumes existing outputs.
    try:
        corr_input = {"url_details": url_details, "ml": ml_result}
        response["evidence_correlation"] = correlate_evidence(corr_input)
    except Exception:
        response["evidence_correlation"] = None

    # Aggregate multi-layer risk without recomputation.
    response["multi_layer_risk"] = aggregate_multi_layer_risk({
        "ml": response.get("ml"),
        "url_details": url_details,
        "final_risk": risk_res,
        "correlated_evidence": response.get("evidence_correlation"),
        "explanation": explanation,
    })

    return response

def analyze_hash(hash_value: str, user_id: int) -> Dict[str, Any]:
    errors = []
    # Accept MD5 (32), SHA1 (40), SHA256 (64) hex strings
    if not all(c in "0123456789abcdefABCDEF" for c in hash_value) or len(hash_value) not in {32, 40, 64}:
        errors.append("Invalid hash format")
        dummy_res = type("obj", (), {"score": 0, "level": "UNKNOWN", "signals": []})()
        dummy_exp = {"summary": "", "key_reasons": []}
        return _build_response(
            analysis_id=None,
            artifact_type="hash",
            details={"hash": hash_value},
            risk_result=dummy_res,
            explanation=dummy_exp,
            errors=errors,
        )
    reputation = get_hash_reputation(hash_value)
    malicious = reputation.get("malicious", False) or reputation.get("suspicious", False)
    score = 1 if malicious else 0
    level = "HIGH" if malicious else "LOW"
    risk_res = type("obj", (), {"score": score, "level": level, "signals": []})()
    explanation = {"summary": f"Hash reputation {'malicious' if malicious else 'clean'}", "key_reasons": []}
    return _build_response(
        analysis_id=None,
        artifact_type="hash",
        details=reputation,
        risk_result=risk_res,
        explanation=explanation,
        errors=errors,
    )

def analyze_email(file_path: str, user_id: int) -> Dict[str, Any]:
    """Analyze an email deterministically and augment with AI feature extraction.

    The deterministic part extracts URLs and runs URL analysis on each. We also
    extract a structured AI feature vector via ``extract_email_ai_features``.
    Since no trained email ML model is present, we expose a ``ml`` field with a
    ``model_available`` flag set to ``False`` and include the extracted features.
    """
    errors = []
    try:
        email_data = email_analyzer(file_path)
    except Exception as exc:
        email_data = {}
        errors.append(str(exc))
    # Deterministic URL extraction and analysis.
    urls = email_data.get("urls", [])
    url_results = []
    for u in urls:
        try:
            res = url_analyzer(u)
            risk = analyze_url_risk(res)
            url_results.append({"url": u, "analysis": res, "risk": {"score": getattr(risk, "score", 0), "level": getattr(risk, "level", "UNKNOWN")}})
        except Exception as exc:
            url_results.append({"url": u, "error": str(exc)})
            errors.append(str(exc))
    max_score = max((r["risk"]["score"] for r in url_results if "risk" in r), default=0)
    level = "HIGH" if max_score > 0 else "LOW"
    risk_res = type("obj", (), {"score": max_score, "level": level, "signals": []})()
    explanation = {"summary": f"Email contains {len(urls)} URLs", "key_reasons": []}
    details = {"email": email_data, "url_analyses": url_results}
    # Deterministic response.
    response = _build_response(
        analysis_id=None,
        artifact_type="email",
        details=details,
        risk_result=risk_res,
        explanation=explanation,
        errors=errors,
    )
    # AI feature extraction (fallback).
    try:
        from src.features.email_ai_features import extract_email_ai_features
        email_features = extract_email_ai_features(email_data)
    except Exception:
        email_features = {}
    response["ml"] = {"model_available": False, "features": email_features}

    # Phase 8A: Evidence correlation for email artifacts.
    try:
        corr_input = {"email_data": email_data}
        response["evidence_correlation"] = correlate_evidence(corr_input)
    except Exception:
        response["evidence_correlation"] = None

    # Phase 8B: Aggregate multi-layer risk for email artifacts.
    response["multi_layer_risk"] = aggregate_multi_layer_risk({
        "ml": response.get("ml"),
        "email": email_data,
        "final_risk": risk_res,
        "correlated_evidence": response.get("evidence_correlation"),
        "explanation": explanation,
    })

    return response

def analyze_qr(file_path: str, user_id: int) -> Dict[str, Any]:
    errors = []
    try:
        qr_res = qr_analyzer(file_path)
    except Exception as exc:
        qr_res = {}
        errors.append(str(exc))
    decoded = qr_res.get("decoded_data")
    is_url = qr_res.get("is_url", False)
    if is_url and decoded:
        url_details = url_analyzer(decoded)
        risk_res = analyze_url_risk(url_details)
        explanation = generate_explanation(risk_res)
        details = {"qr": qr_res, "url_analysis": url_details}
        response = _build_response(
            analysis_id=None,
            artifact_type="qr",
            details=details,
            risk_result=risk_res,
            explanation=explanation,
            errors=errors,
        )
        # Phase 8B: Aggregate multi-layer risk for QR artifacts.
        response["multi_layer_risk"] = aggregate_multi_layer_risk({
            "final_risk": risk_res,
            "explanation": explanation,
        })
        return response
    else:
        risk_res = type("obj", (), {"score": 0, "level": "UNKNOWN", "signals": []})()
        explanation = {"summary": "QR code does not contain a URL", "key_reasons": []}
        details = {"qr": qr_res}
        return _build_response(
            analysis_id=None,
            artifact_type="qr",
            details=details,
            risk_result=risk_res,
            explanation=explanation,
            errors=errors,
        )

def analyze_file(file_path: str, user_id: int) -> Dict[str, Any]:
    errors = []
    try:
        file_hash = _sha256_file(file_path)
        vt_rep = get_hash_reputation(file_hash)
        attachment_info = attachment_analyzer(file_path)
        try:
            embedded_urls = attachment_url_extractor(file_path)
        except Exception:
            embedded_urls = []
        url_results = []
        for u in embedded_urls:
            try:
                res = url_analyzer(u)
                risk = analyze_url_risk(res)
                url_results.append({"url": u, "analysis": res, "risk": {"score": getattr(risk, "score", 0), "level": getattr(risk, "level", "UNKNOWN")}})
            except Exception as exc:
                url_results.append({"url": u, "error": str(exc)})
                errors.append(str(exc))
    except Exception as exc:
        errors.append(str(exc))
        vt_rep = {}
        attachment_info = {}
        url_results = []
        file_hash = ""
    vt_mal = vt_rep.get("malicious", False) or vt_rep.get("suspicious", False)
    max_url_score = max((r["risk"]["score"] for r in url_results if "risk" in r), default=0)
    score = 1 if vt_mal or max_url_score > 0 else 0
    level = "HIGH" if score else "LOW"
    risk_res = type("obj", (), {"score": score, "level": level, "signals": []})()
    explanation = {"summary": f"File analysis result: {'malicious' if vt_mal else 'clean'}", "key_reasons": []}
    details = {
        "file_hash": file_hash,
        "vt_reputation": vt_rep,
        "attachment_info": attachment_info,
        "embedded_url_analyses": url_results,
    }
    response = _build_response(
        analysis_id=None,
        artifact_type="file",
        details=details,
        risk_result=risk_res,
        explanation=explanation,
        errors=errors,
    )

    # Phase 8A: Evidence correlation for file artifacts.
    try:
        corr_input = {
            "url_details": {"virustotal": vt_rep},
            "attachment": attachment_info,
            "embedded_url_analyses": url_results,
        }
        response["evidence_correlation"] = correlate_evidence(corr_input)
    except Exception:
        response["evidence_correlation"] = None
        # Phase 8B: Aggregate multi-layer risk for file artifacts.
        response["multi_layer_risk"] = aggregate_multi_layer_risk({
            "attachment": attachment_info,
            "virustotal": vt_rep,
            "final_risk": risk_res,
            "correlated_evidence": response.get("evidence_correlation"),
            "explanation": explanation,
        })

    return response
