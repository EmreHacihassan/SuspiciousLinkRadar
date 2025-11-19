# app/main.py
from __future__ import annotations
import os, logging
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

try:
    import orjson  # noqa
    from fastapi.responses import ORJSONResponse as DefaultJSONResponse
    JSON_BACKEND = "orjson"
except Exception:
    from fastapi.responses import JSONResponse as DefaultJSONResponse
    JSON_BACKEND = "json"

from slr.models.infer import load_artifact, predict_url

ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT / "models"
DEFAULT_MODEL_PATH = MODELS_DIR / "model_v1.0.pkl"
STATIC_DIR = Path(__file__).resolve().parent / "static"

class PredictRequest(BaseModel):
    url: str = Field()
    threshold: Optional[float] = Field(default=0.80, ge=0.0, le=1.0)

class PredictResponse(BaseModel):
    label: str
    probability: float
    risk_level: str

_ARTIFACT = None

def get_artifact():
    global _ARTIFACT
    if _ARTIFACT is None:
        if not DEFAULT_MODEL_PATH.exists():
            raise HTTPException(status_code=503, detail="Model artifact not found. Train the model first.")
        try:
            _ARTIFACT = load_artifact(str(DEFAULT_MODEL_PATH))
        except Exception as e:
            logging.getLogger("uvicorn.error").exception("Artifact load failed.")
            raise HTTPException(status_code=500, detail=f"Artifact load error: {type(e).__name__}")
    return _ARTIFACT

@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.getLogger("uvicorn.error").info(f"[startup] API hazır (JSON backend={JSON_BACKEND}, model lazy).")
    try:
        yield
    finally:
        logging.getLogger("uvicorn.error").info("[shutdown] API kapanıyor.")

app = FastAPI(
    title="SuspiciousLinkRadar API",
    version="1.0.0",
    default_response_class=DefaultJSONResponse,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8081",
        "http://127.0.0.1:8090",
        "http://localhost:8080",
        "http://localhost:8081",
        "http://localhost:8090",
    ],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", include_in_schema=False)
def index():
    path = STATIC_DIR / "index.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(str(path))

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_exists": DEFAULT_MODEL_PATH.exists(),
        "model_path": str(DEFAULT_MODEL_PATH),
        "json_backend": JSON_BACKEND,
    }

@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    if not isinstance(req.url, str) or not req.url.strip():
        raise HTTPException(status_code=400, detail="Field 'url' must be a non-empty string")
    artifact = get_artifact()
    try:
        out = predict_url(artifact, req.url, threshold=req.threshold if req.threshold is not None else 0.80)
    except HTTPException:
        raise
    except Exception as e:
        logging.getLogger("uvicorn.error").exception("Prediction failed.")
        raise HTTPException(status_code=500, detail=f"Inference error: {type(e).__name__}")
    return PredictResponse(**out)

def run():
    import uvicorn
    host = os.getenv("SLR_HOST", "127.0.0.1")
    port = int(os.getenv("SLR_PORT", os.getenv("PORT", "8080")))
    reload_flag = os.getenv("SLR_RELOAD", "0") == "1"
    uvicorn.run("app.main:app", host=host, port=port, reload=reload_flag, log_level="info")

if __name__ == "__main__":
    run()