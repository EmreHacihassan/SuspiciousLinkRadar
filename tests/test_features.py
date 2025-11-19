from slr.features.extractor import extract
from slr.features.config import FEATURE_NAMES

def test_extract_contains_all_features():
    url = "https://login.example-bank.com/path/a_b-c?x=1&y=2"
    feats = extract(url)
    missing = [f for f in FEATURE_NAMES if f not in feats]
    assert not missing, f"Eksik özellikler: {missing}"

def test_entropy_non_negative():
    feats = extract("http://example.com")
    assert feats["entropy_url"] >= 0.0
