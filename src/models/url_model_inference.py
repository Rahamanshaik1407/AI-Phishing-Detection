"""url_model_inference.py

Provides ML inference for URL analysis.
If a trained model artifact is present (e.g., a joblib file), it will be loaded lazily.
Otherwise, a deterministic fallback response is returned indicating that no model is available.
"""

import os
import json
from typing import Dict, Any

# Feature extraction uses the existing URL feature extractor.
try:
    from src.features.url_features import extract_url_features
except ImportError as e:
    raise ImportError('URL feature extractor is required for ML inference') from e

# Optional joblib import for model deserialization.
try:
    import joblib
except Exception:
    joblib = None  # type: ignore

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "url_random_forest.joblib")


def _load_model():
    """Load the model if the artifact exists and joblib is available.

    Returns:
        model object or None
    """
    if joblib is None:
        return None
    if not os.path.isfile(_MODEL_PATH):
        return None
    try:
        return joblib.load(_MODEL_PATH)
    except Exception:
        # Corrupted or incompatible model – treat as unavailable.
        return None


def predict_url(url: str) -> Dict[str, Any]:
    """Predict phishing probability for a given URL.

    The function extracts the same 14 lexical features used during training, loads the
    saved model (if present), and returns a structured result. When the model artifact
    is missing, ``model_available`` is ``False`` and ``probability`` is ``None``.

    Parameters
    ----------
    url: str
        The URL to evaluate.

    Returns
    -------
    dict
        ``{"model_available": bool, "probability": float | None, "features": dict}``
    """
    # Extract lexical features – reuse existing code path.
    try:
        features = extract_url_features(url)
    except Exception as exc:
        # Feature extraction failed; return error info.
        return {
            "model_available": False,
            "probability": None,
            "features": {},
            "error": str(exc),
        }

    model = _load_model()
    if model is None:
        return {
            "model_available": False,
            "probability": None,
            "features": features,
        }

    # The model was trained on the raw numeric feature dict order. Convert to list.
    # Expected feature order (as used in training scripts):
    feature_order = [
        "url_length", "hostname_length", "path_length", "query_length", "dot_count",
        "hyphen_count", "digit_count", "special_char_count", "subdomain_count",
        "contains_ip", "uses_https", "contains_at", "contains_double_slash", "suspicious_keyword_count",
    ]
    # Ensure all required features are present; missing keys default to 0.
    feature_vector = [float(features.get(k, 0)) for k in feature_order]
    try:
        # Most scikit‑learn models expect a 2‑D array.
        prob = model.predict_proba([feature_vector])[0][1]  # probability of class 1 (phishing)
    except Exception:
        # Fallback if the model does not support predict_proba.
        try:
            pred = model.predict([feature_vector])[0]
            prob = float(pred)
        except Exception:
            prob = None
    return {
        "model_available": True,
        "probability": prob,
        "features": features,
    }
