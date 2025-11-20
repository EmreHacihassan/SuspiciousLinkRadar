from __future__ import annotations
import os, sys, time, logging
from pathlib import Path
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Body, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# ---- Path / Constants ----
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

STATIC_DIR = Path(__file__).parent / "static"
MODELS_DIR = ROOT_DIR / "models"
LABEL_MAP_FILE = MODELS_DIR / "label_map_v1.0.json"
MODEL_VERSION = "v1.0"
APP_VERSION = "1.0.0"
CLASSES = ["benign", "phishing", "malware", "defacement"]

# ---- Logging ----
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("SLR_API")

# ---- JSON backend ----
try:
    from fastapi.responses import ORJSONResponse as BaseJSONResponse  # type: ignore
    JSON_BACKEND = "orjson"
except Exception:
    from fastapi.responses import JSONResponse as BaseJSONResponse  # type: ignore
    JSON_BACKEND = "json"

# ---- Optional model import ----
MODEL_AVAILABLE = False
_ARTIFACT: Optional[Dict[str, Any]] = None
try:
    from slr.models.infer import load_artifact, predict_url  # type: ignore
    MODEL_AVAILABLE = True
except Exception as e:
    log.warning("slr.models.infer bulunamadı (%s) – heuristik mod kullanılacak.", e)

# ---------------- Schemas ----------------
class PredictRequest(BaseModel):
    url: str = Field(..., min_length=3, description="Analiz edilecek URL")
    threshold: float = Field(0.80, ge=0.0, le=1.0)
    debug: bool = Field(False)

    @field_validator("url")
    def _clean(cls, v: str) -> str:
        return v.strip()

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    backend: str
    version: str
    model_version: str

# ---------------- Lifespan ----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _ARTIFACT
    start = time.time()
    if MODEL_AVAILABLE:
        model_path = MODELS_DIR / "model_v1.0.pkl"
        if model_path.exists():
            try:
                _ARTIFACT = load_artifact(str(model_path))
                log.info("Model yüklendi: %s", model_path.name)
            except Exception as e:
                log.error("Model yükleme hatası: %s", e)
                _ARTIFACT = None
        else:
            log.warning("Model dosyası yok: %s", model_path)
    else:
        log.info("Model modülü yok, heuristik mod.")
    log.info("Başlangıç süresi: %.0f ms", (time.time() - start) * 1000)
    yield
    log.info("Kapanış tamamlandı.")

# ---------------- App ----------------
app = FastAPI(
    title="Suspicious Link Radar",
    version=APP_VERSION,
    default_response_class=BaseJSONResponse,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1024)

# No-cache headers for dynamic endpoints
@app.middleware("http")
async def no_cache_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    if request.url.path.startswith(("/predict", "/api/predict", "/health", "/api/health")):
        resp.headers["Cache-Control"] = "no-store"
    return resp

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ---------------- Helpers ----------------
def fabricate_probs(top: str, p: float) -> Dict[str, float]:
    p = max(0.0, min(1.0, p))
    others = [c for c in CLASSES if c != top]
    remain = max(0.0, 1.0 - p)
    share = remain / (len(others) or 1)
    probs = {c: (p if c == top else share) for c in CLASSES}
    return {k: round(v, 6) for k, v in probs.items()}

def heuristic(url: str) -> Dict[str, Any]:
    u = url.lower()
    phishing = 0.75 if any(k in u for k in ["login", "verify", "account", "secure"]) else 0.10
    malware = 0.65 if any(k in u for k in ["download", "exe", "zip"]) else 0.08
    defacement = 0.10
    benign = max(0.05, 1.0 - max(phishing, malware, defacement) - 0.15)
    probs = {
        "benign": benign,
        "phishing": phishing,
        "malware": malware,
        "defacement": defacement,
    }
    label = max(probs.items(), key=lambda x: x[1])[0]
    return {"prediction": label, "probabilities": probs}

def unify(url: str, threshold: float, debug: bool) -> Dict[str, Any]:
    t_start = time.time()
    if MODEL_AVAILABLE and _ARTIFACT is not None:
        try:
            raw = predict_url(_ARTIFACT, url, threshold=threshold)  # type: ignore
        except Exception as e:
            log.error("Model inference hatası: %s", e)
            raw = {}
    else:
        raw = heuristic(url)

    prediction = raw.get("prediction") or raw.get("label") or "benign"
    probs = raw.get("probabilities") or raw.get("probs") or raw.get("scores")
    if not isinstance(probs, dict):
        # probability alanı varsa tahmini dağıt üret
        base_prob = float(raw.get("probability", 0.6))
        probs = fabricate_probs(prediction, base_prob)

    # Temizlik + sınıf filtreleme
    clean_probs: Dict[str, float] = {}
    for c in CLASSES:
        v = probs.get(c, 0.0)
        try:
            clean_probs[c] = float(v)
        except Exception:
            clean_probs[c] = 0.0

    # Risk seviyesi (phishing/malware/defacement max)
    threat_score = max(clean_probs.get("phishing", 0.0),
                       clean_probs.get("malware", 0.0),
                       clean_probs.get("defacement", 0.0))
    risk_level = "high" if threat_score >= 0.6 else "medium" if threat_score >= 0.3 else "low"
    latency_ms = round((time.time() - t_start) * 1000, 2)

    resp: Dict[str, Any] = {
        "url": url,
        "prediction": prediction,
        "label": prediction,                    # alias
        "probabilities": clean_probs,
        "probability": clean_probs.get(prediction, 0.0),
        "confidence": clean_probs.get(prediction, 0.0),
        "risk_level": risk_level,
        "threat_score": threat_score,
        "model_version": MODEL_VERSION,
        "backend": JSON_BACKEND,
        "latency_ms": latency_ms,
        "timestamp": int(time.time() * 1000),
        "version": APP_VERSION,
    }
    if debug:
        resp["raw"] = raw
    return resp

# ---------------- Routes ----------------
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/static/index.html")

@app.get("/health", response_model=HealthResponse)
def health():
    return {
        "status": "active",
        "model_loaded": _ARTIFACT is not None,
        "backend": JSON_BACKEND,
        "version": APP_VERSION,
        "model_version": MODEL_VERSION,
    }

@app.post("/predict")
def predict_post(payload: PredictRequest = Body(...)):
    return unify(payload.url, payload.threshold, payload.debug)

@app.get("/predict")
def predict_get(
    url: str = Query(..., min_length=3),
    threshold: float = Query(0.80, ge=0.0, le=1.0),
    debug: bool = Query(False),
):
    return unify(url.strip(), threshold, debug)

# Aliases
app.add_api_route("/api/predict", predict_post, methods=["POST"])
app.add_api_route("/api/predict", predict_get, methods=["GET"])
app.add_api_route("/api/health", health, methods=["GET"])

# ---------------- Local run ----------------
if __name__ == "__main__":
    import uvicorn
    host = os.getenv("SLR_HOST", "127.0.0.1")
    port = int(os.getenv("SLR_PORT", "8081"))
    print(f"\nUI:   http://{host}:{port}/static/index.html")
    print(f"API:  http://{host}:{port}/predict\n")
    uvicorn.run("app.main:app", host=host, port=port, reload=True, reload_dirs=[str(ROOT_DIR)])