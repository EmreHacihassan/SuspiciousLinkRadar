from __future__ import annotations

import sys
import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

# -----------------------------------------------------------------------------
# 1. Yol Ayarları (Path Fix) - En Kritik Bölüm
# -----------------------------------------------------------------------------
# Bu blok, 'python app/main.py' çalıştırıldığında 'slr' klasörünün
# Python tarafından görülmesini sağlar.
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, ConfigDict

# -----------------------------------------------------------------------------
# Yapılandırma
# -----------------------------------------------------------------------------
# Hızlı JSON kütüphanesi varsa onu kullan, yoksa standart olanı
try:
    import orjson
    from fastapi.responses import ORJSONResponse as DefaultJSONResponse
    JSON_BACKEND = "orjson"
except ImportError:
    from fastapi.responses import JSONResponse as DefaultJSONResponse
    JSON_BACKEND = "json"

MODELS_DIR: Path = ROOT_DIR / "models"
DEFAULT_MODEL_PATH: Path = MODELS_DIR / "model_v1.0.pkl"
STATIC_DIR: Path = Path(__file__).resolve().parent / "static"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("SLR_API")

# -----------------------------------------------------------------------------
# SLR Modülünü İçe Aktarma
# -----------------------------------------------------------------------------
SLR_MODULE_AVAILABLE = False
try:
    from slr.models.infer import load_artifact, predict_url
    SLR_MODULE_AVAILABLE = True
except ImportError as e:
    logger.error(f"⚠️ KRİTİK: 'slr' modülü yüklenemedi. Hata: {e}")
    logger.error("👉 Çözüm: Terminalde 'pip install -e .' komutunu çalıştırın.")

# -----------------------------------------------------------------------------
# Veri Modelleri (Schema)
# -----------------------------------------------------------------------------
class PredictRequest(BaseModel):
    url: str = Field(..., description="Analiz edilecek URL adresi", min_length=3)
    threshold: float = Field(default=0.80, ge=0.0, le=1.0, description="Risk eşiği")

    @field_validator("url")
    @classmethod
    def clean_url(cls, v: str) -> str:
        return v.strip()

class PredictResponse(BaseModel):
    label: str
    probability: float
    risk_level: str

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    backend: str
    version: str = "1.0.0"
    model_config = ConfigDict(protected_namespaces=())

# -----------------------------------------------------------------------------
# Uygulama Başlatma/Durdurma (Lifespan)
# -----------------------------------------------------------------------------
_ARTIFACT: Optional[Dict[str, Any]] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _ARTIFACT
    logger.info(f"🚀 Suspicious Link Radar Başlatılıyor... (Backend: {JSON_BACKEND})")
    
    if SLR_MODULE_AVAILABLE:
        if DEFAULT_MODEL_PATH.exists():
            try:
                _ARTIFACT = load_artifact(str(DEFAULT_MODEL_PATH))
                logger.info(f"✅ Model başarıyla yüklendi: {DEFAULT_MODEL_PATH.name}")
            except Exception as e:
                logger.error(f"❌ Model dosyası bozuk olabilir: {e}")
        else:
            logger.warning(f"⚠️ Model dosyası bulunamadı: {DEFAULT_MODEL_PATH}")
            logger.warning("👉 Tahminleme yapmak için önce modeli eğitmelisiniz (SLR.ipynb).")
    
    yield
    logger.info("👋 Uygulama kapatılıyor.")

# -----------------------------------------------------------------------------
# FastAPI Kurulumu
# -----------------------------------------------------------------------------
app = FastAPI(
    title="Suspicious Link Radar",
    version="1.0.0",
    default_response_class=DefaultJSONResponse,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1024)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# -----------------------------------------------------------------------------
# Endpointler
# -----------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/static/index.html")

@app.get("/health", response_model=HealthResponse)
def health():
    return {
        "status": "active",
        "model_loaded": _ARTIFACT is not None,
        "backend": JSON_BACKEND
    }

@app.post("/predict", response_model=PredictResponse)
def predict_endpoint(req: PredictRequest):
    if not SLR_MODULE_AVAILABLE:
        raise HTTPException(status_code=500, detail="Sunucu kurulum hatası: 'slr' modülü yok.")
    
    if _ARTIFACT is None:
        raise HTTPException(status_code=503, detail="Model yüklü değil. Lütfen sistemi eğitin.")

    try:
        return predict_url(_ARTIFACT, req.url, threshold=req.threshold)
    except Exception as e:
        logger.error(f"Tahmin hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# -----------------------------------------------------------------------------
# Başlatıcı
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    
    PORT = int(os.getenv("SLR_PORT", 8090))
    HOST = os.getenv("SLR_HOST", "127.0.0.1")
    
    print(f"\n🔌 Sunucu: http://{HOST}:{PORT}")
    print(f"💻 Arayüz: http://{HOST}:{PORT}/static/index.html\n")
    
    uvicorn.run(
        "app.main:app", 
        host=HOST, 
        port=PORT, 
        reload=True, 
        reload_dirs=[str(ROOT_DIR)]
    )