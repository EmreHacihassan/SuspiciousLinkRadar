# slr/models/train.py
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, classification_report
from sklearn.model_selection import (
    GridSearchCV,
    StratifiedGroupKFold,
    StratifiedKFold,
    KFold,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from slr.features.config import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    LABEL_MAP as IDX2LABEL,
    to_vector,
)
from slr.features.extractor import extract

ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = ROOT / "data" / "processed"
MODELS_DIR = ROOT / "models"

def safe_read(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, low_memory=False)
    if "label" not in df.columns:
        raise ValueError(f"Beklenen 'label' kolonu yok: {path}")
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    bad = int(df["label"].isna().sum())
    if bad:
        print(f"[WARN] {path.name}: {bad} satırda label NaN atılıyor.")
        df = df[df["label"].notna()].copy()
    df["label"] = df["label"].astype(int)
    return df

def load_splits(processed_dir: Path):
    tr = safe_read(processed_dir / "train.csv")
    va = safe_read(processed_dir / "val.csv")
    te = safe_read(processed_dir / "test.csv")
    return tr, va, te

def df_to_matrix(d: pd.DataFrame):
    feats_list = [extract(u) for u in d["url_norm"].astype(str).tolist()]
    X = np.array([to_vector(f) for f in feats_list], dtype=float)
    y = d["label"].astype(int).values
    groups = d["group"].astype(str).values
    return X, y, groups

def choose_cv(y: np.ndarray, groups: np.ndarray, desired: int, seed: int):
    y = np.asarray(y)
    groups = np.asarray(groups)
    n_samples = len(y)
    desired = min(desired, n_samples) if n_samples else desired
    n_classes = len(np.unique(y))
    uniq_groups = len(np.unique(groups))
    bc = np.bincount(y) if y.size else np.array([])
    min_c = int(bc.min()) if bc.size else 0

    if n_samples < 2 or n_classes < 2 or min_c < 2:
        return None, "none"
    if uniq_groups >= desired and min_c >= desired and desired >= 2:
        return StratifiedGroupKFold(n_splits=desired, shuffle=True, random_state=seed), "sgkf"
    if min_c >= desired and n_classes >= 2 and desired >= 2:
        return StratifiedKFold(n_splits=desired, shuffle=True, random_state=seed), "skf"
    if n_classes >= 2:
        return StratifiedKFold(n_splits=2, shuffle=True, random_state=seed), "skf2"
    return None, "none"

def train(n_jobs: int = -1, cv_folds: int = 5, seed: int = 42) -> Dict[str, Any]:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    tr, va, te = load_splits(PROCESSED_DIR)

    X_tr, y_tr, g_tr = df_to_matrix(tr)
    X_va, y_va, _ = df_to_matrix(va)
    X_te, y_te, _ = df_to_matrix(te)

    # Tiny or single-class fallback: merge val into train if needed
    if len(y_tr) < 2 or len(np.unique(y_tr)) < 2:
        print("[WARN] Tiny or single-class train split; merging validation into train.")
        tr_merged = pd.concat([tr, va], ignore_index=True)
        X_tr, y_tr, g_tr = df_to_matrix(tr_merged)

    n_samples = X_tr.shape[0]
    unique_classes = len(np.unique(y_tr))
    need_skip_cv = (
        n_samples < cv_folds
        or unique_classes < 2
        or min(np.bincount(y_tr)) < 2
    )

    pipe_base = lambda C=1.0: Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    C=C,
                    max_iter=3000,
                    class_weight="balanced",
                    solver="lbfgs",
                    random_state=seed,
                ),
            ),
        ]
    )

    if need_skip_cv:
        print(f"[WARN] Skipping CV (n_samples={n_samples}, unique_classes={unique_classes}). Single fit.")
        model = pipe_base(C=1.0)
        model.fit(X_tr, y_tr)
        return _finalize(
            model,
            {"clf__C": 1.0},
            float("nan"),
            X_va,
            y_va,
            X_te,
            y_te,
            extra_flags={"cv_skipped": True},
        )

    cv, cv_kind = choose_cv(y_tr, g_tr, desired=cv_folds, seed=seed)
    if cv is None:
        print("[WARN] No valid CV strategy; single fit.")
        model = pipe_base(C=1.0)
        model.fit(X_tr, y_tr)
        return _finalize(
            model,
            {"clf__C": 1.0},
            float("nan"),
            X_va,
            y_va,
            X_te,
            y_te,
            extra_flags={"cv_skipped": True, "cv_kind": cv_kind},
        )

    param_grid = {"clf__C": [0.1, 1.0, 3.0, 10.0]}

    def run_gs(nj, cv_obj, cv_name):
        gs = GridSearchCV(
            pipe_base(),
            param_grid=param_grid,
            scoring="f1_macro",
            cv=cv_obj,
            n_jobs=nj,
            verbose=1,
            error_score=np.nan,
        )
        gs.fit(X_tr, y_tr, groups=g_tr)
        means = gs.cv_results_.get("mean_test_score")
        if means is None or np.all(np.isnan(means)):
            raise RuntimeError(f"All CV folds failed for {cv_name}")
        return gs

    try:
        gs = run_gs(n_jobs, cv, cv_kind)
    except Exception as e1:
        print(f"[WARN] GridSearch(cv={cv_kind}, n_jobs={n_jobs}) hata: {e1}  StratifiedKFold(2) dene")
        try:
            gs = run_gs(1, StratifiedKFold(n_splits=2, shuffle=True, random_state=seed), "skf2")
        except Exception as e2:
            print(f"[WARN] GridSearch(skf2) hata: {e2}  Tek fit.")
            model = pipe_base(C=1.0)
            model.fit(X_tr, y_tr)
            return _finalize(
                model,
                {"clf__C": 1.0},
                float("nan"),
                X_va,
                y_va,
                X_te,
                y_te,
                extra_flags={"cv_skipped": True, "fallback_error": str(e2)},
            )

    best = gs.best_estimator_
    best_params = gs.best_params_
    cv_score = float(gs.best_score_)
    return _finalize(best, best_params, cv_score, X_va, y_va, X_te, y_te, extra_flags={"cv_kind": cv_kind})

def _finalize(best, best_params, cv_score, X_va, y_va, X_te, y_te, extra_flags: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    val_pred = best.predict(X_va)
    test_pred = best.predict(X_te)
    val_f1 = float(f1_score(y_va, val_pred, average="macro"))
    test_f1 = float(f1_score(y_te, test_pred, average="macro"))

    idx_order = sorted(IDX2LABEL.keys())
    target_names = [IDX2LABEL[i] for i in idx_order]

    val_report = classification_report(
        y_va, val_pred, labels=idx_order, target_names=target_names, output_dict=True, zero_division=0
    )
    test_report = classification_report(
        y_te, test_pred, labels=idx_order, target_names=target_names, output_dict=True, zero_division=0
    )

    metrics = {
        "algo": "lr",
        "feature_version": FEATURE_VERSION,
        "best_params": best_params,
        "cv_f1_macro": cv_score,
        "val_f1_macro": val_f1,
        "test_f1_macro": test_f1,
        "val_report": val_report,
        "test_report": test_report,
    }
    if extra_flags:
        metrics.update(extra_flags)

    artifact = {
        "model": best,
        "feature_names": FEATURE_NAMES,
        "feature_version": FEATURE_VERSION,
        "label_map": IDX2LABEL,
    }
    joblib.dump(artifact, MODELS_DIR / "model_v1.0.pkl")
    (MODELS_DIR / "metrics_v1.0.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    (MODELS_DIR / "label_map_v1.0.json").write_text(
        json.dumps(IDX2LABEL, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (MODELS_DIR / "feature_config_v1.0.json").write_text(
        json.dumps({"feature_version": FEATURE_VERSION, "feature_names": FEATURE_NAMES}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "best_params": best_params,
                "cv_f1_macro": cv_score,
                "val_f1_macro": val_f1,
                "test_f1_macro": test_f1,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return metrics

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n_jobs", type=int, default=-1)
    ap.add_argument("--cv_folds", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    train(n_jobs=args.n_jobs, cv_folds=args.cv_folds, seed=args.seed)

if __name__ == "__main__":
    main()