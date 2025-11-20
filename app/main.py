from __future__ import annotations
import os, sys, time, logging, hashlib, threading
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from contextlib import asynccontextmanager
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import FastAPI, Body, Query, Request, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import RedirectResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, field_validator, ConfigDict

# ====== Path / Constants ======
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

STATIC_DIR = Path(__file__).parent / "static"
MODELS_DIR = ROOT_DIR / "models"
MODEL_FILE = MODELS_DIR / "model_v1.0.pkl"
MODEL_VERSION = "v1.0"
APP_VERSION = "1.1.0"
CLASSES = ["benign", "phishing", "malware", "defacement"]

API_KEY_EXPECTED = os.getenv("SLR_API_KEY")  # boş ise koruma yok
RATE_LIMIT_WINDOW_SEC = int(os.getenv("SLR_RATE_WINDOW", "60"))
RATE_LIMIT_MAX = int(os.getenv("SLR_RATE_MAX", "120"))  # pencere başına çağrı (IP)
ALLOW_RELOAD_ARTIFACT = os.getenv("SLR_AUTO_RELOAD", "1") == "1"

# ====== Logging ======
logging.basicConfig(
    level=os.getenv("SLR_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("SLR_API")

# ====== JSON backend ======
try:
    from fastapi.responses import ORJSONResponse as BaseJSONResponse  # type: ignore
    JSON_BACKEND = "orjson"
except Exception:
    from fastapi.responses import JSONResponse as BaseJSONResponse  # type: ignore
    JSON_BACKEND = "json"

# ====== Optional model import ======
MODEL_AVAILABLE = False
_ARTIFACT: Optional[Dict[str, Any]] = None
_ARTIFACT_LAST_HASH: Optional[str] = None
_ARTIFACT_LOCK = threading.Lock()

try:
    from slr.models.infer import load_artifact, predict_url  # type: ignore
    MODEL_AVAILABLE = True
except Exception as e:
    log.warning("slr.models.infer import başarısız (%s) → heuristik mod.", e)

# ====== Rate Limit State ======
_calls: Dict[str, list[float]] = defaultdict(list)

def _rate_limit(ip: str) -> bool:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SEC
    bucket = _calls[ip]
    # temizlik
    while bucket and bucket[0] < window_start:
        bucket.pop(0)
    if len(bucket) >= RATE_LIMIT_MAX:
        return False
    bucket.append(now)
    return True

# ====== Schemas ======
class PredictRequest(BaseModel):
    url: str = Field(..., min_length=3)
    threshold: float = Field(0.80, ge=0.0, le=1.0)
    debug: bool = Field(False)

    @field_validator("url")
    @classmethod
    def _clean(cls, v: str) -> str:
        return v.strip()

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    backend: str
    version: str
    model_version: str
    latency_ms: float
    rate_limit_max: int
    rate_limit_window_sec: int
    model_config = ConfigDict(protected_namespaces=())  # pydantic uyarı fix

class MetricsResponse(BaseModel):
    uptime_seconds: float
    total_requests: int
    predict_requests: int
    model_version: str
    version: str
    backend: str
    last_reload_ts: Optional[int] = None
    model_loaded: bool

# ====== Global Metrics ======
START_TIME = time.time()
TOTAL_REQUESTS = 0
PREDICT_REQUESTS = 0
LAST_RELOAD_TS: Optional[int] = None

# ====== Lifespan / Artifact Loader ======
def _file_hash(path: Path) -> str:
    try:
        h = hashlib.md5(path.read_bytes()).hexdigest()
        return h
    except Exception:
        return ""

def _reload_artifact(force: bool = False) -> None:
    global _ARTIFACT, _ARTIFACT_LAST_HASH, LAST_RELOAD_TS
    if not MODEL_AVAILABLE:
        return
    if not MODEL_FILE.exists():
        log.warning("Model dosyası yok: %s", MODEL_FILE)
        return
    new_hash = _file_hash(MODEL_FILE)
    if not force and _ARTIFACT_LAST_HASH == new_hash:
        return
    with _ARTIFACT_LOCK:
        try:
            _ARTIFACT = load_artifact(str(MODEL_FILE))
            _ARTIFACT_LAST_HASH = new_hash
            LAST_RELOAD_TS = int(time.time() * 1000)
            log.info("Model artefakt yeniden yüklendi (%s, hash=%s)", MODEL_FILE.name, new_hash[:8])
        except Exception as e:
            log.error("Model yükleme hatası: %s", e)
            _ARTIFACT = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    t0 = time.time()
    if MODEL_AVAILABLE:
        _reload_artifact(force=True)
    else:
        log.info("Model modülü yok → heuristik fallback.")
    log.info("Başlangıç süresi: %.0f ms", (time.time() - t0) * 1000)
    yield
    log.info("Uygulama kapanıyor.")

# ====== App Init ======
app = FastAPI(
    title="Suspicious Link Radar",
    version=APP_VERSION,
    default_response_class=BaseJSONResponse,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS
allow_origins_env = os.getenv("SLR_ALLOW_ORIGINS", "*")
allow_origins = [o.strip() for o in allow_origins_env.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Static
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ====== Error Handlers ======
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return BaseJSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "detail": exc.errors(),
            "path": request.url.path,
            "timestamp": int(time.time() * 1000),
        },
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return BaseJSONResponse(
        status_code=exc.status_code,
        content={
            "error": "http_exception",
            "detail": exc.detail,
            "path": request.url.path,
            "timestamp": int(time.time() * 1000),
        },
    )

# ====== Middleware ======
@app.middleware("http")
async def global_mw(request: Request, call_next):
    global TOTAL_REQUESTS, PREDICT_REQUESTS
    start = time.time()
    path = request.url.path
    TOTAL_REQUESTS += 1
    if path.startswith("/predict"):
        PREDICT_REQUESTS += 1

    # Basit güvenlik başlıkları
    headers_extra = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    # Rate limit sadece /predict uçları
    client_ip = request.client.host if request.client else "unknown"
    if path.startswith("/predict") and RATE_LIMIT_MAX > 0:
        if not _rate_limit(client_ip):
            return BaseJSONResponse(
                status_code=429,
                content={
                    "error": "rate_limited",
                    "detail": f"Too many requests (max {RATE_LIMIT_MAX}/{RATE_LIMIT_WINDOW_SEC}s)",
                    "ip": client_ip,
                },
            )

    # API Key kontrol (opsiyonel)
    if API_KEY_EXPECTED and path.startswith("/predict"):
        key = request.headers.get("x-api-key")
        if key != API_KEY_EXPECTED:
            return BaseJSONResponse(
                status_code=401,
                content={"error": "unauthorized", "detail": "Invalid or missing x-api-key"},
            )

    resp: Response = await call_next(request)

    # no-store dinamik uçlar
    if path.startswith(("/predict", "/api/predict", "/health", "/api/health", "/metrics")):
        resp.headers["Cache-Control"] = "no-store"

    # ETag (predict yanıtları için hash)
    if path.startswith("/predict") and resp.media_type == "application/json":
        body = getattr(resp, "body", None)
        if body:
            etag = hashlib.sha1(body).hexdigest()
            resp.headers["ETag"] = etag

    for k, v in headers_extra.items():
        resp.headers.setdefault(k, v)

    duration_ms = (time.time() - start) * 1000
    resp.headers["X-Request-Latency-ms"] = f"{duration_ms:.1f}"
    return resp

# ====== Helpers ======
def fabricate_probs(top: str, p: float) -> Dict[str, float]:
    p = max(0.0, min(1.0, float(p)))
    others = [c for c in CLASSES if c != top]
    rest = max(0.0, 1.0 - p)
    share = rest / (len(others) or 1)
    return {c: (p if c == top else share) for c in CLASSES}

def heuristic(url: str) -> Dict[str, Any]:
    u = (url or "").lower()
    phishing = 0.75 if any(k in u for k in ["login", "verify", "account", "secure"]) else 0.10
    malware = 0.65 if any(k in u for k in ["download", "exe", "zip"]) else 0.08
    defacement = 0.10
    benign = max(0.05, 1.0 - max(phishing, malware, defacement) - 0.15)
    probs = {"benign": benign, "phishing": phishing, "malware": malware, "defacement": defacement}
    label = max(probs.items(), key=lambda x: x[1])[0]
    threat_score = max(probs["phishing"], probs["malware"], probs["defacement"])
    risk_level = "high" if threat_score >= 0.6 else "medium" if threat_score >= 0.3 else "low"
    return {
        "prediction": label,
        "probabilities": probs,
        "probability": probs[label],
        "risk_level": risk_level,
        "threat_score": threat_score,
    }

def _maybe_reload_artifact():
    if ALLOW_RELOAD_ARTIFACT and MODEL_AVAILABLE:
        _reload_artifact(force=False)

def unify(url: str, threshold: float, debug: bool) -> Dict[str, Any]:
    t0 = time.time()
    _maybe_reload_artifact()
    if MODEL_AVAILABLE and _ARTIFACT is not None:
        try:
            raw = predict_url(_ARTIFACT, url, threshold=threshold)  # type: ignore
        except Exception as e:
            log.error("Inference hatası: %s", e)
            raw = {}
    else:
        raw = heuristic(url)

    pred = raw.get("prediction") or raw.get("label") or "benign"
    probs = raw.get("probabilities") or raw.get("probs") or raw.get("scores")
    if not isinstance(probs, dict):
        probs = fabricate_probs(pred, float(raw.get("probability", 0.6)))

    clean = {c: float(probs.get(c, 0.0)) for c in CLASSES}
    threat_score = max(clean["phishing"], clean["malware"], clean["defacement"])
    risk_level = raw.get("risk_level") or ("high" if threat_score >= 0.6 else "medium" if threat_score >= 0.3 else "low")

    out: Dict[str, Any] = {
        "url": url,
        "prediction": pred,
        "label": pred,
        "probabilities": clean,
        "probability": float(clean.get(pred, 0.0)),
        "confidence": float(clean.get(pred, 0.0)),
        "risk_level": risk_level,
        "threat_score": threat_score,
        "model_version": MODEL_VERSION,
        "backend": JSON_BACKEND,
        "version": APP_VERSION,
        "latency_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": int(time.time() * 1000),
        "auto_reload": ALLOW_RELOAD_ARTIFACT,
    }
    if debug:
        out["raw"] = raw
    return out

# ====== Routes ======
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/static/index.html")

@app.get("/health", response_model=HealthResponse, tags=["system"])
def health():
    return {
        "status": "active",
        "model_loaded": _ARTIFACT is not None,
        "backend": JSON_BACKEND,
        "version": APP_VERSION,
        "model_version": MODEL_VERSION,
        "latency_ms": 0.0,
        "rate_limit_max": RATE_LIMIT_MAX,
        "rate_limit_window_sec": RATE_LIMIT_WINDOW_SEC,
    }

@app.get("/metrics", response_model=MetricsResponse, tags=["system"])
def metrics():
    return {
        "uptime_seconds": round(time.time() - START_TIME, 1),
        "total_requests": TOTAL_REQUESTS,
        "predict_requests": PREDICT_REQUESTS,
        "model_version": MODEL_VERSION,
        "version": APP_VERSION,
        "backend": JSON_BACKEND,
        "last_reload_ts": LAST_RELOAD_TS,
        "model_loaded": _ARTIFACT is not None,
    }

@app.post("/predict", tags=["inference"])
def predict_post(
    payload: PredictRequest = Body(...),
    x_api_key: Optional[str] = Header(None),
):
    return unify(payload.url, payload.threshold, payload.debug)

@app.get("/predict", tags=["inference"])
def predict_get(
    url: str = Query(..., min_length=3),
    threshold: float = Query(0.80, ge=0.0, le=1.0),
    debug: bool = Query(False),
    x_api_key: Optional[str] = Header(None),
):
    return unify(url.strip(), threshold, debug)

# Legacy /api aliases
app.add_api_route("/api/predict", predict_post, methods=["POST"])
app.add_api_route("/api/predict", predict_get, methods=["GET"])
app.add_api_route("/api/health", health, methods=["GET"])
app.add_api_route("/api/metrics", metrics, methods=["GET"])

# Manual artifact reload endpoint (secured by API key if set)
@app.post("/admin/reload", tags=["admin"])
def admin_reload(x_api_key: Optional[str] = Header(None)):
    if API_KEY_EXPECTED and x_api_key != API_KEY_EXPECTED:
        raise HTTPException(status_code=401, detail="invalid api key")
    _reload_artifact(force=True)
    return {"status": "reloaded", "timestamp": LAST_RELOAD_TS, "model_loaded": _ARTIFACT is not None}

# Simple ping
@app.get("/ping", tags=["system"])
def ping():
    return PlainTextResponse("pong", headers={"Cache-Control": "no-store"})

# ====== Local run ======
if __name__ == "__main__":
    import uvicorn
    host = os.getenv("SLR_HOST", "127.0.0.1")
    port = int(os.getenv("SLR_PORT", "8081"))
    log.info("Başlatılıyor: http://%s:%d/", host, port)
    print(f"\nUI:    http://{host}:{port}/static/index.html")
    print(f"Docs:  http://{host}:{port}/docs")
    print(f"API:   http://{host}:{port}/predict\n")
    uvicorn.run("app.main:app", host=host, port=port, reload=True, reload_dirs=[str(ROOT_DIR)])