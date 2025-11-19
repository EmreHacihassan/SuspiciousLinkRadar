from __future__ import annotations

from typing import Dict, Any, Tuple

import joblib
import numpy as np

from slr.features.extractor import extract


def load_artifact(path: str) -> Dict[str, Any]:
    return joblib.load(path)


def _vectorize(features: Dict[str, float], feature_names) -> np.ndarray:
    return np.array([float(features.get(name, 0.0)) for name in feature_names], dtype=float).reshape(1, -1)


def _softmax(scores: np.ndarray) -> np.ndarray:
    s = scores - scores.max(axis=1, keepdims=True)
    exps = np.exp(s)
    return exps / np.clip(exps.sum(axis=1, keepdims=True), 1e-12, None)


def _class_probabilities(model, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)
        classes_ = getattr(model, "classes_", np.arange(probs.shape[1]))
        return probs, classes_
    if hasattr(model, "decision_function"):
        scores = model.decision_function(X)
        if scores.ndim == 1:
            scores = np.vstack([-scores, scores]).T
        probs = _softmax(scores)
        classes_ = getattr(model, "classes_", np.arange(probs.shape[1]))
        return probs, classes_
    preds = model.predict(X)
    classes_ = getattr(model, "classes_", np.unique(preds))
    probs = np.zeros((preds.shape[0], len(classes_)), dtype=float)
    for i, c in enumerate(classes_):
        probs[:, i] = (preds == c).astype(float)
    return probs, classes_


def _risk_policy(label_str: str, prob: float, threshold: float) -> str:
    if label_str == "benign" and prob >= threshold:
        return "safe"
    if label_str != "benign" and prob >= threshold:
        return "danger"
    return "caution"


def predict_url(artifact: Dict[str, Any], url: str, threshold: float = 0.80) -> Dict[str, Any]:
    model = artifact["model"]
    feature_names = artifact.get("feature_names")
    label_map = artifact.get("label_map")

    feats = extract(url)
    if feature_names is None:
        feature_names = list(feats.keys())

    X = _vectorize(feats, feature_names)
    probs, classes_ = _class_probabilities(model, X)

    class_idx = int(classes_[int(np.argmax(probs[0]))])
    label_str = label_map.get(class_idx, str(class_idx)) if isinstance(label_map, dict) else str(class_idx)
    prob = float(probs[0, np.argmax(probs[0])])

    risk = _risk_policy(label_str, prob, threshold)
    return {
        "label": label_str,
        "probability": round(prob, 6),
        "risk_level": risk,
    }