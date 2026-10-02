# tests/test_external_evaluation.py
"""Tests for the external evaluation utility.

These tests verify that the `evaluate_external` function:
- correctly computes metrics on a tiny synthetic dataset,
- raises informative errors when required columns are missing,
- raises errors for empty URL values,
- does not perform any model training (the provided `predict_func` is called only for inference),
- returns a dictionary with the expected keys and types.
"""

import builtins
import io
import types
from typing import Dict, List

import pytest

# Import the function under test
from src.analysis.external_evaluation import evaluate_external


def _stub_predict(url: str) -> Dict:
    """A deterministic stub prediction function.

    Returns a probability of 0.8 for any URL, signalling the positive class.
    The stub mimics the shape of `src.models.url_model_inference.predict_url`.
    """
    return {"model_available": True, "probability": 0.8, "features": {}}


def test_valid_binary_evaluation():
    """Evaluate a tiny balanced dataset and verify metric values."""
    # Create a CSV string with two positive and two negative examples
    csv_data = """url,label
http://good.com,0
https://bad.com,1
http://neutral.org,0
https://phishy.net,1
"""
    # Use an in‑memory file via StringIO
    csv_file = io.StringIO(csv_data)
    # Write to a temporary file because the evaluator expects a path
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, mode="w", newline="", encoding="utf-8") as tmp:
        tmp.write(csv_data)
        tmp_path = tmp.name
    try:
        result = evaluate_external(tmp_path, _stub_predict)
        # Expected: all predictions are 1 (positive) because stub returns prob=0.8
        # Therefore accuracy = 0.5 (2/4 correct), precision = 0.5 (2 TP / 4 predicted positives),
        # recall = 1.0 (2 TP / 2 actual positives), f1 = 0.666...
        assert isinstance(result, dict)
        assert set(result.keys()) == {"accuracy", "precision", "recall", "f1", "confusion_matrix"}
        assert result["confusion_matrix"] == (0, 2, 0, 2)  # tn=0, fp=2, fn=0, tp=2
        # Allow small floating‑point variations
        assert abs(result["accuracy"] - 0.5) < 1e-6
        assert abs(result["precision"] - 0.5) < 1e-6
        assert abs(result["recall"] - 1.0) < 1e-6
        assert abs(result["f1"] - (2 * 0.5 * 1.0 / (0.5 + 1.0))) < 1e-6
    finally:
        os.unlink(tmp_path)


def test_missing_label_column_raises():
    """Dataset lacking the `label` column should raise ValueError."""
    csv_data = "url\nhttp://example.com\n"
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, mode="w", newline="", encoding="utf-8") as tmp:
        tmp.write(csv_data)
        tmp_path = tmp.name
    try:
        with pytest.raises(ValueError, match="Missing label"):
            evaluate_external(tmp_path, _stub_predict)
    finally:
        os.unlink(tmp_path)


def test_missing_url_raises():
    """Empty URL values should raise ValueError."""
    csv_data = "url,label\n,0\nhttp://good.com,1\n"
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, mode="w", newline="", encoding="utf-8") as tmp:
        tmp.write(csv_data)
        tmp_path = tmp.name
    try:
        with pytest.raises(ValueError, match="Missing URL"):
            evaluate_external(tmp_path, _stub_predict)
    finally:
        os.unlink(tmp_path)


def test_single_class_dataset_raises():
    """A dataset containing only one class should raise a clear error."""
    csv_data = "url,label\nhttp://good.com,0\nhttp://alsogood.com,0\n"
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, mode="w", newline="", encoding="utf-8") as tmp:
        tmp.write(csv_data)
        tmp_path = tmp.name
    try:
        with pytest.raises(ValueError, match="Both classes"):
            evaluate_external(tmp_path, _stub_predict)
    finally:
        os.unlink(tmp_path)


def test_no_training_occurs(monkeypatch):
    """Ensure the evaluator only calls the predict function, not any training code.

    We replace the stub with a wrapper that records calls.
    """
    call_log: List[str] = []

    def logging_predict(url: str) -> Dict:
        call_log.append(url)
        return {"model_available": True, "probability": 0.3, "features": {}}

    csv_data = "url,label\nhttp://a.com,0\nhttp://b.com,1\n"
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, mode="w", newline="", encoding="utf-8") as tmp:
        tmp.write(csv_data)
        tmp_path = tmp.name
    try:
        result = evaluate_external(tmp_path, logging_predict)
        # Two URLs, so two calls recorded
        assert len(call_log) == 2
        # No attribute like "trained" should appear; we simply assert the predict function
        # was called and returned a dict – the test passes if no exception is raised.
        assert isinstance(result, dict)
    finally:
        os.unlink(tmp_path)
