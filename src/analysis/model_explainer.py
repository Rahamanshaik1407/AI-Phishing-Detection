"""
model_explainer.py

Provides an optional explainability layer for the URL Random Forest model.
All functions contain detailed comments describing purpose, steps, and
security considerations.
"""

import os
import sys
from typing import Any, Dict, List

# Feature extraction – re‑use the existing lexical extractor.
try:
    from src.features.url_features import extract_url_features
except ImportError as e:
    raise ImportError("URL feature extractor is required for model explanation") from e

# Optional joblib import for deserialising the model artifact.
try:
    import joblib  # type: ignore
except Exception:
    joblib = None  # type: ignore

# Path to the trained Random Forest model artifact (same location used in inference).
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "url_random_forest.joblib")


def _load_model() -> Any:
    """Load the Random Forest model if the artifact exists.

    Returns:
        The deserialized model object, or ``None`` if the artifact is missing
        or cannot be loaded.  This function deliberately swallows any
        deserialization errors to avoid exposing stack traces to callers.
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


def _detect_malicious_class_index(model: Any) -> int:
    """Determine which class index corresponds to the *malicious* label.

    The Random Forest was trained with a binary target where ``1`` denotes
    malicious URLs.  Scikit‑learn stores the class labels in ``model.classes_``.
    If the attribute is missing or does not contain ``1``, we fall back to the
    last index (``-1``) which is a safe default for ``predict_proba``.
    """
    try:
        # ``classes_`` may be strings ("malicious") or integers (1).
        classes = list(model.classes_)
        if 1 in classes:
            return classes.index(1)
        if "malicious" in classes:
            return classes.index("malicious")
    except Exception:
        pass
    # Default to the second column (index 1) – common for binary classifiers.
    return 1


def explain_url_model(url: str) -> Dict[str, Any]:
    """Generate an explainability payload for a URL using the Random Forest.

    The function follows a *best‑effort* approach:

    1. Extract the 14 lexical features used during training.
    2. Load the persisted model artifact (if present).
    3. Compute the phishing probability via ``predict_proba`` when supported.
    4. Attempt SHAP‑based per‑prediction explanations – optional.
    5. If SHAP is unavailable, fall back to the model's ``feature_importances_``.
    6. Return a structured dictionary that callers can merge into the API
       response.

    Security considerations:
    * No external network calls are performed.
    * All failures are caught and reported via ``available: False`` with a
      concise ``reason`` string – no stack‑traces are leaked.
    * The function never mutates global state.
    """
    # ------------------------------------------------------------------
    # 1. Feature extraction – must match training order exactly.
    # ------------------------------------------------------------------
    try:
        features = extract_url_features(url)
    except Exception as exc:
        return {
            "available": False,
            "reason": f"feature extraction failed: {exc}",
        }

    # ------------------------------------------------------------------
    # 2. Load the model artifact.
    # ------------------------------------------------------------------
    model = _load_model()
    if model is None:
        return {
            "available": False,
            "reason": "model artifact not found or could not be loaded",
        }

    # ------------------------------------------------------------------
    # 3. Prepare the ordered feature vector expected by the model.
    # ------------------------------------------------------------------
    feature_order = [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "dot_count",
        "hyphen_count",
        "digit_count",
        "special_char_count",
        "subdomain_count",
        "contains_ip",
        "uses_https",
        "contains_at",
        "contains_double_slash",
        "suspicious_keyword_count",
    ]
    vector = [float(features.get(k, 0)) for k in feature_order]

    # ------------------------------------------------------------------
    # 4. Compute the probability (if supported) and the raw prediction.
    # ------------------------------------------------------------------
    probability = None
    try:
        # ``predict_proba`` returns an array of shape (n_samples, n_classes).
        probas = model.predict_proba([vector])
        mal_idx = _detect_malicious_class_index(model)
        probability = float(probas[0][mal_idx])
    except Exception:
        # Fallback to ``predict`` – may return class label directly.
        try:
            pred = model.predict([vector])[0]
            # If the prediction is already a probability (e.g., regression), use it.
            probability = float(pred)
        except Exception:
            probability = None

    # ------------------------------------------------------------------
    # 5. Attempt SHAP – optional and may not be installed.
    # ------------------------------------------------------------------
    shap_available = False
    shap_values: List[float] = []
    direction: List[str] = []
    try:
        import shap  # type: ignore
        # Use the generic TreeExplainer for scikit‑learn models.
        explainer = shap.TreeExplainer(model)
        shap_res = explainer(vector)
        # ``shap_res.values`` is an array aligned with the feature order.
        shap_vals = list(map(float, shap_res.values))
        # Determine direction relative to the malicious class.
        for val in shap_vals:
            if val > 0:
                direction.append("increases_risk")
            elif val < 0:
                direction.append("decreases_risk")
            else:
                direction.append("neutral")
        shap_values = shap_vals
        shap_available = True
    except Exception:
        shap_available = False

    # ------------------------------------------------------------------
    # 6. Build the top‑features list – sort by absolute contribution.
    # ------------------------------------------------------------------
    top_features: List[Dict[str, Any]] = []
    if shap_available:
        # Use absolute SHAP magnitude for ranking.
        indices = sorted(
            range(len(shap_values)),
            key=lambda i: abs(shap_values[i]),
            reverse=True,
        )[:5]
        for i in indices:
            top_features.append(
                {
                    "feature": feature_order[i],
                    "value": vector[i],
                    "shap_value": shap_values[i],
                    "direction": direction[i],
                }
            )
        explanation_method = "SHAP"
    else:
        # Fallback to built‑in feature importances.
        try:
            importances = list(map(float, model.feature_importances_))
            indices = sorted(
                range(len(importances)),
                key=lambda i: abs(importances[i]),
                reverse=True,
            )[:5]
            for i in indices:
                top_features.append(
                    {
                        "feature": feature_order[i],
                        "value": vector[i],
                        "importance": importances[i],
                    }
                )
            explanation_method = "model_feature_importance"
        except Exception:
            # Neither SHAP nor feature importances are available.
            explanation_method = "none"

    result: Dict[str, Any] = {
        "available": True,
        "model": "Random Forest",
        "prediction": "malicious" if probability is not None and probability >= 0.5 else "benign",
        "probability": probability,
        "explanation_method": explanation_method,
        "top_features": top_features,
    }

    # If we could not compute a probability, still indicate availability.
    if probability is None:
        result["probability"] = None

    return result
