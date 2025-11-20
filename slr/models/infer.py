"""
Model yükleme ve tahmin (UI ile uyumlu standart çıktı).
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, Optional

import numpy as np
import joblib

from slr.utils.url import normalize_url
from slr.features.extractor import extract
from slr.features.config import FEATURE_NAMES, to_vector, LABEL_MAP as IDX2LABEL

CLASSES = ["benign", "phishing", "malware", "defacement"]

__all__ = ["load_artifact", "predict_url"]

def _project_root() -> Path:
    # slr/models/infer.py → .. / .. / (repo root)
    return Path(__file__).resolve().parents[2]

def load_artifact(path: Optional[str] = None) -> Dict[str, Any]:
    """
    models/model_v1.0.pkl dosyasını yükler.
    Dönen sözlük beklenen anahtarlar: model, feature_names, feature_version, label_map
    """
    if path is None:
        path = str(_project_root() / "models" / "model_v1.0.pkl")
    artifact = joblib.load(path)
    # Güçlü doğrulama (opsiyonel anahtarlar yoksa varsayılan ata)
    if "label_map" not in artifact:
        artifact["label_map"] = IDX2LABEL
    if "feature_names" not in artifact:
        artifact["feature_names"] = FEATURE_NAMES
    return artifact

def _softmax(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    x = x - np.max(x, axis=-1, keepdims=True)
    e = np.exp(x)
    s = e / np.maximum(e.sum(axis=-1, keepdims=True), 1e-12)
    return s

def _proba_from_model(model, X: np.ndarray) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        p = model.predict_proba(X)
        return np.asarray(p, dtype=float)
    if hasattr(model, "decision_function"):
        s = model.decision_function(X)
        if s.ndim == 1:
            s = np.vstack([-s, s]).T
        return _softmax(s)
    # fallback: sabit olasılıklar
    k = getattr(model, "classes_", [0, 1])
    out = np.full((X.shape[0], len(k)), 1.0 / len(k), dtype=float)
    return out

def _build_prob_dict(idx2label: Dict[int, str], vec: np.ndarray) -> Dict[str, float]:
    prob_dict = {k: 0.0 for k in CLASSES}
    for i, p in enumerate(vec):
        lab = idx2label.get(i)  # ör: {0:'benign',1:'defacement',2:'phishing',3:'malware'}
        if lab in prob_dict:
            prob_dict[lab] = float(p)
    # normalizasyon (küçük nümerik sapmalar için)
    s = sum(prob_dict.values())
    if s > 0:
        for k in list(prob_dict.keys()):
            prob_dict[k] = float(prob_dict[k] / s)
    return prob_dict

def predict_url(artifact: Dict[str, Any], url: str, threshold: float = 0.8) -> Dict[str, Any]:
    """
    UI ile uyumlu standart çıktı döndürür:
    {
      "prediction": "<class>",
      "probabilities": {"benign":..,"phishing":..,"malware":..,"defacement":..},
      "probability": <float>,
      "risk_level": "low|medium|high"
    }
    """
    if not isinstance(url, str) or len(url.strip()) < 3:
        raise ValueError("url boş olamaz")
    url_norm = normalize_url(url)

    # Özellik çıkarımı → vektör
    feats = extract(url_norm)
    vec = to_vector(feats)  # FEATURE_NAMES sırasına göre
    X = np.asarray(vec, dtype=float).reshape(1, -1)

    model = artifact["model"]
    idx2label: Dict[int, str] = artifact.get("label_map", IDX2LABEL)

    # Olasılıklar
    proba = _proba_from_model(model, X)[0]  # shape: (K,)
    probs = _build_prob_dict(idx2label, proba)

    # Karar ve metrikler
    prediction = max(probs.items(), key=lambda x: x[1])[0]
    probability = float(probs[prediction])
    threat_score = max(probs["phishing"], probs["malware"], probs["defacement"])
    risk_level = "high" if threat_score >= 0.6 else "medium" if threat_score >= 0.3 else "low"

    return {
        "prediction": prediction,
        "probabilities": probs,
        "probability": probability,
        "risk_level": risk_level,
    }