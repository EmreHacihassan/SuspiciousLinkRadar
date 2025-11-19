from typing import List

FEATURE_VERSION = "v1.0"

SUSPICIOUS_KEYWORDS: List[str] = [
    "login","secure","verify","update","bank","free","offer",
    "click","confirm","signin","account","password","webscr",
    "ebayisapi","mail","bonus","gift","prize"
]

BASE_FEATURES: List[str] = [
    "url_length","host_length","path_length","query_length",
    "dot_count","dash_count","underscore_count","at_count",
    "slash_count","question_count","equal_count",
    "digit_count","letter_count","digit_ratio","entropy_url",
    "param_count","uses_https","has_port","ip_literal",
    "subdomain_count","tld_length","double_slash_in_path"
]

FEATURE_NAMES: List[str] = BASE_FEATURES + [f"kw_{k}" for k in SUSPICIOUS_KEYWORDS]

LABEL_MAP = {0: "benign", 1: "defacement", 2: "phishing", 3: "malware"}
INV_LABEL_MAP = {v: k for k, v in LABEL_MAP.items()}

def to_vector(feats: dict):
    return [feats.get(name, 0.0) for name in FEATURE_NAMES]
