from __future__ import annotations

from collections import Counter
from math import log2
from typing import Dict
from urllib.parse import urlsplit, unquote

import tldextract

from slr.features.config import SUSPICIOUS_KEYWORDS, FEATURE_NAMES
from slr.utils.url import normalize_url, is_ip_literal


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    cnt = Counter(text)
    total = float(len(text))
    ent = 0.0
    for c in cnt.values():
        p = c / total
        ent -= p * log2(p)
    return float(ent)


def extract(url: str) -> Dict[str, float]:
    u = normalize_url(url)
    parts = urlsplit(u)

    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    query = parts.query or ""

    full = unquote(u)
    full_lower = full.lower()
    path_lower = path.lower()
    query_lower = query.lower()

    # tldextract: subdomain/domain/suffix
    try:
        ext = tldextract.extract(host)
        subdomain = ext.subdomain or ""
        suffix = ext.suffix or ""
        subdomain_count = 0 if not subdomain else len([seg for seg in subdomain.split(".") if seg])
        tld_len = len(suffix)
    except Exception:
        subdomain_count = 0
        tld_len = 0

    # Temel uzunluklar
    url_length = float(len(full))
    host_length = float(len(host))
    path_length = float(len(path))
    query_length = float(len(query))

    # Sayaçlar
    dot_count = float(host.count("."))
    dash_count = float(full.count("-"))
    underscore_count = float(full.count("_"))
    at_count = float(full.count("@"))
    slash_count = float(full.count("/"))
    question_count = float(full.count("?"))
    equal_count = float(full.count("="))
    digit_count = float(sum(ch.isdigit() for ch in full))
    letter_count = float(sum(ch.isalpha() for ch in full))

    denom = digit_count + letter_count
    digit_ratio = float(digit_count / denom) if denom > 0 else 0.0

    entropy_url = _shannon_entropy(full)

    # Parametre sayısı (= query’deki anahtar sayısı)
    param_count = float(len([p for p in query.split("&") if p])) if query else 0.0

    uses_https = 1.0 if scheme == "https" else 0.0
    has_port = 1.0 if parts.port is not None else 0.0
    ip_lit = 1.0 if is_ip_literal(host) else 0.0
    double_slash_in_path = 1.0 if "//" in path else 0.0

    feats: Dict[str, float] = {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "query_length": query_length,
        "dot_count": dot_count,
        "dash_count": dash_count,
        "underscore_count": underscore_count,
        "at_count": at_count,
        "slash_count": slash_count,
        "question_count": question_count,
        "equal_count": equal_count,
        "digit_count": digit_count,
        "letter_count": letter_count,
        "digit_ratio": digit_ratio,
        "entropy_url": entropy_url,
        "param_count": param_count,
        "uses_https": uses_https,
        "has_port": has_port,
        "ip_literal": ip_lit,
        "subdomain_count": float(subdomain_count),
        "tld_length": float(tld_len),
        "double_slash_in_path": double_slash_in_path,
    }

    # Anahtar kelime bayrakları (host, path, query içinde arama)
    haystack = f"{host} {path_lower} {query_lower}"
    for kw in SUSPICIOUS_KEYWORDS:
        feats[f"kw_{kw}"] = 1.0 if kw in haystack else 0.0

    # Güvence: tüm FEATURE_NAMES anahtarları mevcut olsun
    for name in FEATURE_NAMES:
        if name not in feats:
            feats[name] = 0.0

    return feats