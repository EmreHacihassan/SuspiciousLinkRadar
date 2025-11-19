# 🛡️ SuspiciousLinkRadar (SLR) — Şüpheli URL Tespit Sistemi

Versiyon: 1.0.0  
Durum: Geliştirme Aşamasında (Local Deployment)

SuspiciousLinkRadar (SLR), girilen URL’leri analiz ederek siber güvenlik risklerini (Phishing, Malware, Defacement) tespit eden, makine öğrenmesi tabanlı bir web uygulamasıdır. Sistem, URL’den çıkarılan sözel (lexical), host/protokol ve anahtar kelime tabanlı özellikleri kullanarak sınıflandırma yapar ve sonuçları kullanıcıya net risk durumlarıyla sunar.

## 🎯 Amaç ve Temel Hedefler
- Oltalama ve zararlı yazılım içeren site erişimlerini son kullanıcı düzeyinde proaktif engellemek.
- URL analizi süreçlerini otomatikleştirerek farkındalık ve güvenlik hijyenini artırmak.
- Yüksek doğruluk ve düşük gecikme ile tamamen yerel (offline) çalışabilen hafif bir çözüm sunmak.

## ✨ Öne Çıkan Özellikler
- Çok sınıflı sınıflandırma: Benign, Defacement, Phishing, Malware
- Özellik çıkarımı: Lexical + Host/Protocol + Anahtar Kelime bayrakları
- Hızlı çıkarım (low-latency) ve tek-binary Model + Feature config sürümleme
- Net risk durumları ve erişilebilir arayüz (kontrast ve ikon/metin beraber)
- FastAPI tabanlı backend ve açık JSON API sözleşmesi

---

## 📊 Veri Seti ve Analiz

Kaynaklar (örnek): ISCX-URL-2016, PhishTank, MalwareDomainList/BlackList vb.  
Toplam örnek (ör.): 651,191 URL

Sınıf dağılımı (örnek):
- Benign: ~65.7%
- Defacement: ~14.8%
- Phishing: ~14.5%
- Malware: ~5.0%

Dikkat edilmesi gerekenler:
- Sınıf dengesizliği: `class_weight="balanced"` veya yalnızca train set üzerinde SMOTE.
- Sızıntı önleme: Domain/grup tabanlı bölme (aynı domain train/test’e dağılmasın), URL normalizasyonu ve deduplikasyon.
- Bölme: Stratified + GroupKFold (domain) önerilir.

Veri lisansları ve kullanım şartları kaynak bazında kontrol edilmelidir.

---

## 🧩 Özellik Mühendisliği (Feature Engineering)

Lexical:
- Uzunluklar: URL/host/path/query uzunlukları
- Karakter istatistikleri: `.` `-` `_` `@` `/` `?` `=` sayı/oranları
- Rakam/harf oranı, Shannon entropy, TLD uzunluğu
- Çoklu `//`, aşırı uzun query, parametre sayısı

Host/Protokol:
- HTTPS kullanımı, özel port varlığı
- IP literal kullanımı (host’un IP olması)
- Alt domain sayısı (derinlik), TLD şüpheliliği
- `@` sembolü varlığı (kimlik gizleme girişimleri)

Anahtar Kelimeler:
- `login`, `secure`, `verify`, `update`, `bank`, `free`, `offer`, `click`, `confirm`, `signin` vb.

Notlar:
- Ağaç tabanlı modeller için zorunlu ölçekleme yoktur; ancak özellik sözlüğü/sürümünü `feature_config.json` ile sabitlemek önerilir.

---

## 🤖 Modelleme ve Değerlendirme

Model seçenekleri:
- Baseline: Logistic Regression
- Güçlü alternatifler: Random Forest, LightGBM, XGBoost (öneri: LightGBM)

Doğrulama:
- Stratified 5-Fold CV (mümkünse domain GroupKFold)
- Metrikler: Macro-F1 (öncelikli), sınıf bazlı F1, ROC-AUC ve PR-AUC
- Kalibrasyon: Platt veya Isotonic (olasılık güvenilirliği için)

Model artefaktları:
- `models/model_v1.0.pkl`
- `models/feature_config_v1.0.pkl`
- `models/label_map_v1.0.json`

Açıklanabilirlik:
- Global feature importance + örnek bazlı SHAP açıklamaları (opsiyonel, analiz modunda)

---

## 🚦 Risk Eşikleri ve UI Davranışı

Sınıf kararı + olasılık ile risk seviyesi birlikte değerlendirilir:

- 🟢 Güvenli (Benign): sınıf=Benign ve p ≥ 0.80
  - Davranış: Link aktif; bilgi mesajı
- 🟡 Tahrifat (Defacement): sınıf=Defacement ve p ≥ 0.80
  - Davranış: Uyarı mesajı; giriş yapmama önerisi
- 🟠 Oltalama (Phishing): sınıf=Phishing ve p ≥ 0.80
  - Davranış: Link gizle/pasifleştir; güçlü uyarı
- 🔴 Zararlı Yazılım (Malware): sınıf=Malware ve p ≥ 0.80
  - Davranış: Erişim önerilmez; kritik uyarı

Belirsiz bölge:
- 0.50 ≤ p < 0.80 → “Dikkat” bandı; link varsayılan kapalı olabilir
- p < 0.50 → “Kararsız” mesajı; manuel doğrulama öner

Eşikler, işletim senaryonuza göre ROC/PR eğrilerine bakılarak ayarlanmalıdır.

---

## 🧪 API (FastAPI) Sözleşmesi

Endpoint: `POST /predict`  
İstek:
```json
{
  "url": "https://example.com/login?ref=mail"
}