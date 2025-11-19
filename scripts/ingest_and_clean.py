#!/usr/bin/env python
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlsplit

import pandas as pd

# tldextract kullanımı (deprecation: registered_domain → top_domain_under_public_suffix)
try:
    import tldextract
except ModuleNotFoundError:
    sys.stderr.write("HATA: tldextract yok. Kurulum: python -m pip install tldextract\n")
    raise

# Proje içi yardımcılar
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slr.utils.url import normalize_url  # noqa: E402

# Label haritası
TYPE_TO_IDX = {"benign": 0, "defacement": 1, "phishing": 2, "malware": 3}


def etld_plus_one(host: str) -> str:
    if not host:
        return "unknown"
    try:
        ext = tldextract.extract(host)
        # Yeni isim: top_domain_under_public_suffix; eskiye (registered_domain) fallback
        domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
        return domain or host or "unknown"
    except Exception:
        return "unknown"


def host_group(url_norm: str) -> str:
    try:
        return urlsplit(url_norm).hostname or "unknown"
    except Exception:
        return "unknown"


def summarize_class_distribution(df: pd.DataFrame, col: str = "type") -> Dict[str, float]:
    return {k: float(round(v, 6)) for k, v in df[col].value_counts(normalize=True).to_dict().items()}


def build_groups(df: pd.DataFrame, mode: str) -> pd.Series:
    if mode == "etld_plus_one":
        return df["url_norm"].map(lambda u: etld_plus_one(urlsplit(u).hostname or "")).astype(str)
    if mode == "host":
        return df["url_norm"].map(host_group).astype(str)
    raise ValueError(f"Geçersiz group_mode: {mode}")


def clean_and_prepare(df: pd.DataFrame, group_mode: str, min_url_len: int) -> tuple[pd.DataFrame, Dict[str, Any]]:
    original_count = len(df)
    df["type"] = df["type"].astype(str).str.lower().str.strip()

    initial_dist = summarize_class_distribution(df, "type")
    known = set(TYPE_TO_IDX.keys())
    mask_known = df["type"].isin(known)
    unknown_types = sorted(df.loc[~mask_known, "type"].unique().tolist())
    df = df.loc[mask_known].reset_index(drop=True)

    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() >= min_url_len].reset_index(drop=True)

    df["url_norm"] = df["url"].map(normalize_url).astype(str)
    df = df.dropna(subset=["url_norm"]).reset_index(drop=True)
    df = df.drop_duplicates(subset=["url_norm"]).reset_index(drop=True)

    df["label"] = df["type"].map(TYPE_TO_IDX)
    bad = int(df["label"].isna().sum())
    if bad:
        raise ValueError(f"Label mapping sonrası beklenmeyen NaN label ({bad}).")
    df["label"] = df["label"].astype(int)

    df["group"] = build_groups(df, group_mode)
    final_dist = summarize_class_distribution(df, "type")

    meta = {
        "original_count": original_count,
        "after_known_filter": int(len(df)),
        "unknown_types": unknown_types,
        "initial_class_dist": initial_dist,
        "final_class_dist": final_dist,
        "group_mode": group_mode,
        "min_url_len": min_url_len,
        "distinct_groups": int(df["group"].nunique()),
    }
    return df, meta


def _group_shuffle_split(df: pd.DataFrame, seed: int, test_size: float = 0.2) -> tuple[pd.DataFrame, pd.DataFrame]:
    from sklearn.model_selection import GroupShuffleSplit

    y = df["label"].values
    g = df["group"].values
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    tr_idx, te_idx = next(gss.split(df, y, groups=g))
    return df.iloc[tr_idx].reset_index(drop=True), df.iloc[te_idx].reset_index(drop=True)


def stratified_group_split(
    df: pd.DataFrame, seed: int, outer_splits: int, inner_splits: int
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """
    Önce SGKF dener; sınıf-sayısı/ grup sayısı yeterli değilse GroupShuffleSplit fallback uygular.
    """
    from sklearn.model_selection import StratifiedGroupKFold

    # Outer
    y = df["label"].values
    g = df["group"].values
    min_c = int(df["label"].value_counts().min()) if len(df) else 0
    ug = int(df["group"].nunique())

    outer = min(max(2, outer_splits), max(2, min_c), max(2, ug))
    used_outer = outer

    try:
        sgkf = StratifiedGroupKFold(n_splits=outer, shuffle=True, random_state=seed)
        tr_idx, te_idx = next(sgkf.split(df, y, g))
        df_tr_tmp = df.iloc[tr_idx].reset_index(drop=True)
        df_te = df.iloc[te_idx].reset_index(drop=True)
    except Exception:
        # Fallback: grup korumalı shuffle
        df_tr_tmp, df_te = _group_shuffle_split(df, seed, test_size=1.0 / max(outer_splits, 2))
        used_outer = 2

    # Inner
    y2 = df_tr_tmp["label"].values
    g2 = df_tr_tmp["group"].values
    min_c2 = int(df_tr_tmp["label"].value_counts().min()) if len(df_tr_tmp) else 0
    ug2 = int(df_tr_tmp["group"].nunique())
    inner = min(max(2, inner_splits), max(2, min_c2), max(2, ug2))
    used_inner = inner

    try:
        sgkf2 = StratifiedGroupKFold(n_splits=inner, shuffle=True, random_state=seed)
        tr2, va2 = next(sgkf2.split(df_tr_tmp, y2, g2))
        df_tr = df_tr_tmp.iloc[tr2].reset_index(drop=True)
        df_va = df_tr_tmp.iloc[va2].reset_index(drop=True)
    except Exception:
        df_tr, df_va = _group_shuffle_split(df_tr_tmp, seed, test_size=1.0 / max(inner_splits, 2))
        used_inner = 2

    split_meta = {
        "requested_outer_splits": int(outer_splits),
        "requested_inner_splits": int(inner_splits),
        "actual_outer_splits": int(used_outer),
        "actual_inner_splits": int(used_inner),
        "train_count": int(len(df_tr)),
        "val_count": int(len(df_va)),
        "test_count": int(len(df_te)),
    }
    return df_tr, df_va, df_te, split_meta


def write_splits(
    out_dir: Path, df_train: pd.DataFrame, df_val: pd.DataFrame, df_test: pd.DataFrame, parquet: bool
) -> None:
    keep = ["url", "url_norm", "label", "group"]
    csv_args = dict(index=False, quoting=csv.QUOTE_MINIMAL, escapechar="\\", lineterminator="\n")

    out_dir.mkdir(parents=True, exist_ok=True)
    df_train[keep].to_csv(out_dir / "train.csv", **csv_args)
    df_val[keep].to_csv(out_dir / "val.csv", **csv_args)
    df_test[keep].to_csv(out_dir / "test.csv", **csv_args)

    if parquet:
        try:
            df_train[keep].to_parquet(out_dir / "train.parquet", index=False)
            df_val[keep].to_parquet(out_dir / "val.parquet", index=False)
            df_test[keep].to_parquet(out_dir / "test.parquet", index=False)
        except Exception as e:
            print(f"[WARN] Parquet yazılamadı: {e}. Devam ediliyor (CSV hazır).")


def repair_processed_splits(out_dir: Path) -> Dict[str, int]:
    """
    Yazım sonrası güvenlik: label sütununu numeriğe coerçe eder, NaN olanları atar, int'e çevirir.
    CSV'leri yerinde yeniden yazar ve düşen satır sayılarını döndürür.
    """
    dropped_counts: Dict[str, int] = {}
    keep = ["url", "url_norm", "label", "group"]
    for name in ["train.csv", "val.csv", "test.csv"]:
        fp = out_dir / name
        if not fp.exists():
            continue
        df = pd.read_csv(fp, dtype=str, low_memory=False)
        df["label"] = pd.to_numeric(df["label"], errors="coerce")
        dropped = int(df["label"].isna().sum())
        if dropped:
            print(f"{name}: dropping {dropped} bad label rows")
        df = df[df["label"].notna()].copy()
        df["label"] = df["label"].astype(int)
        df[keep].to_csv(fp, index=False, quoting=csv.QUOTE_MINIMAL, escapechar="\\", lineterminator="\n")
        dropped_counts[name] = dropped
    if not dropped_counts:
        print("Processed splits repaired: no issues found.")
    else:
        print("Processed splits repaired.")
    return dropped_counts


def read_back_counts(out_dir: Path) -> Dict[str, int]:
    counts = {}
    for name in ["train.csv", "val.csv", "test.csv"]:
        fp = out_dir / name
        if fp.exists():
            counts[name.split(".")[0]] = int(sum(1 for _ in open(fp, "r", encoding="utf-8", newline="")))
            # üst satır header dahil; DataFrame ile daha doğru:
            try:
                n = int(pd.read_csv(fp).shape[0])
                counts[name.split(".")[0]] = n
            except Exception:
                pass
    return counts


def build_metadata(clean_meta: Dict[str, Any], split_meta: Dict[str, Any], final_counts: Dict[str, int], seed: int) -> Dict[str, Any]:
    m = dict(clean_meta)
    m.update(
        {
            "counts": {
                "train": int(final_counts.get("train", split_meta["train_count"])),
                "val": int(final_counts.get("val", split_meta["val_count"])),
                "test": int(final_counts.get("test", split_meta["test_count"])),
            },
            "splits": {
                "requested_outer": int(split_meta["requested_outer_splits"]),
                "requested_inner": int(split_meta["requested_inner_splits"]),
                "actual_outer": int(split_meta["actual_outer_splits"]),
                "actual_inner": int(split_meta["actual_inner_splits"]),
            },
            "seed": int(seed),
            "label_map": {v: k for k, v in TYPE_TO_IDX.items()},
        }
    )
    return m


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser("SuspiciousLinkRadar ingest & clean")
    p.add_argument("--input", type=str, default=str(ROOT / "data" / "raw" / "malicious_phish.csv"))
    p.add_argument("--out", type=str, default=str(ROOT / "data" / "processed"))
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--outer_splits", type=int, default=5)
    p.add_argument("--inner_splits", type=int, default=5)
    p.add_argument("--group_mode", choices=["etld_plus_one", "host"], default="etld_plus_one")
    p.add_argument("--min_url_len", type=int, default=4)
    p.add_argument("--parquet", action="store_true")
    p.add_argument("--force", action="store_true")
    return p.parse_args()


def maybe_clear(out_dir: Path, force: bool) -> None:
    if not force:
        return
    patterns = ["train.csv", "val.csv", "test.csv", "train.parquet", "val.parquet", "test.parquet", "metadata.json"]
    removed = []
    for name in patterns:
        fp = out_dir / name
        if fp.exists():
            fp.unlink()
            removed.append(name)
    if removed:
        print("Önceki dosyalar silindi:", removed)


def main() -> None:
    a = parse_args()
    input_csv = Path(a.input)
    out_dir = Path(a.out)

    assert input_csv.exists(), f"Girdi yok: {input_csv}"
    maybe_clear(out_dir, a.force)

    # Ham veriyi yükle
    df = pd.read_csv(input_csv)
    assert {"url", "type"}.issubset(df.columns), "Gerekli kolonlar eksik: url, type"

    # Temizle + hazırla
    df_clean, clean_meta = clean_and_prepare(df, group_mode=a.group_mode, min_url_len=a.min_url_len)

    # Split (SGKF → fallback)
    df_train, df_val, df_test, split_meta = stratified_group_split(
        df_clean, seed=a.seed, outer_splits=a.outer_splits, inner_splits=a.inner_splits
    )

    # Güvence (yazımdan önce)
    assert df_train["label"].isna().sum() == 0
    assert df_val["label"].isna().sum() == 0
    assert df_test["label"].isna().sum() == 0

    # Yaz
    write_splits(out_dir, df_train, df_val, df_test, parquet=a.parquet)

    # Yazım sonrası etiketleri güvene al
    repair_processed_splits(out_dir)

    # Geri okuma ile son sayımlar
    final_counts = read_back_counts(out_dir)

    # Metadata
    meta = build_metadata(clean_meta, split_meta, final_counts, seed=a.seed)
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    # Özet
    print("=== Özet ===")
    print(
        json.dumps(
            {
                "counts": meta["counts"],
                "unknown_types": clean_meta["unknown_types"],
                "distinct_groups": clean_meta["distinct_groups"],
                "group_mode": clean_meta["group_mode"],
                "outer_splits_actual": split_meta["actual_outer_splits"],
                "inner_splits_actual": split_meta["actual_inner_splits"],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    print(f"Tamamlandı → {out_dir}")


if __name__ == "__main__":
    main()