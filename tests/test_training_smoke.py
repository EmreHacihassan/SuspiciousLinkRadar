import pandas as pd
from slr.models.train import train

def test_smoke_training(tmp_path, monkeypatch):
    # Küçük sentetik veri
    data = {
        "url": [
            "http://example.com",
            "http://secure-login.bank.com/login",
            "http://phish.update-secure.example",
            "http://malware.bad-site.xyz/install",
            "http://defacement.vuln.example/restore",
        ],
        "type": ["benign","benign","phishing","malware","defacement"],
    }
    df = pd.DataFrame(data)

    raw_dir = tmp_path / "data" / "raw"
    proc_dir = tmp_path / "data" / "processed"
    raw_dir.mkdir(parents=True)
    proc_dir.mkdir(parents=True)
    df.to_csv(raw_dir / "malicious_phish.csv", index=False)

    # Ingestion adımları (küçük veri için doğrudan fonksiyonlar)
    from scripts.ingest_and_clean import clean_and_prepare, stratified_group_split, write_splits
    df_clean, _ = clean_and_prepare(df, group_mode="host", min_url_len=4)
    df_train, df_val, df_test, _ = stratified_group_split(df_clean, seed=42, outer_splits=2, inner_splits=2)
    write_splits(proc_dir, df_train, df_val, df_test, parquet=False)

    # Eğitim modülünü geçici processed/models yoluna yönlendir
    monkeypatch.setattr("slr.models.train.PROCESSED_DIR", proc_dir)
    monkeypatch.setattr("slr.models.train.MODELS_DIR", tmp_path / "models")

    metrics = train(n_jobs=1, cv_folds=2, seed=42)
    assert "cv_f1_macro" in metrics
