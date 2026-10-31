import json
import logging
import os
import time
from typing import List, Optional

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app import config
from app.allowlist import load_known_domains, match_known_domain
from app.anatomy import url_anatomy
from app.explain import explain
from app.utils.extractor import FEATURE_NAMES, extract_features, normalize_url

logger = logging.getLogger("url_shield")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="URL Shield AI - Malicious URL Detection API",
    description="Design and Implementation of a Machine Learning Based System for Malicious URL Detection (Master's Thesis Project)",
    version="1.3",
)

MODEL_PATH = config.MODEL_PATH
MAX_BATCH = 200


def load_model(path: str):
    if not os.path.exists(path):
        logger.error("Model file not found: %s (run `python -m app.train` inside backend/)", path)
        return None
    try:
        loaded = joblib.load(path)
    except Exception:
        logger.exception("Model could not be loaded: %s", path)
        return None
    # Guard against a model trained with a different feature set
    n_expected = getattr(loaded, "n_features_in_", len(FEATURE_NAMES))
    if n_expected != len(FEATURE_NAMES):
        logger.error("Model expects %s features but the extractor produces %s. "
                     "Retrain with `python -m app.train`.", n_expected, len(FEATURE_NAMES))
        return None
    logger.info("Model loaded: %s", path)
    return loaded


def load_meta() -> dict:
    try:
        with open(config.MODEL_META_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


model = load_model(MODEL_PATH)
model_meta = load_meta()
KNOWN_DOMAINS = load_known_domains()
logger.info("Known-domain allow-list: %s domains", len(KNOWN_DOMAINS))


def risk_level(p: float) -> str:
    if p >= config.RISK_HIGH:
        return "high"
    if p >= config.RISK_MEDIUM:
        return "medium"
    return "low"


class URLRequest(BaseModel):
    url: str


class BatchRequest(BaseModel):
    urls: List[str] = Field(..., max_length=MAX_BATCH)


class Reason(BaseModel):
    feature: str
    label: str
    value: str
    impact: float       # change in malicious probability caused by this feature
    direction: str


class URLPart(BaseModel):
    part: str          # scheme | www | subdomain | domain | tld | host | port | path | query
    text: str
    level: str         # ok | warn | flag | muted
    notes: List[str]


class PredictionResponse(BaseModel):
    url: str
    prediction: str                 # "Benign" | "Malicious" (decision threshold 0.5)
    risk_level: str                 # "low" | "medium" | "high" (after the allow-list)
    model_risk_level: str           # risk level from the model alone
    known_domain: Optional[str] = None   # set when the URL is on a known popular domain
    confidence: float               # probability of the predicted class
    malicious_probability: float    # probability of the "Malicious" class
    explanation: List[Reason] = []
    anatomy: List[URLPart] = []
    latency_ms: float


class BatchItem(BaseModel):
    url: str
    prediction: Optional[str] = None
    risk_level: Optional[str] = None
    model_risk_level: Optional[str] = None
    known_domain: Optional[str] = None
    malicious_probability: Optional[float] = None
    error: Optional[str] = None


def _require_model():
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Train the model first.")


@app.get("/")
def read_root():
    return {"message": "URL Shield AI Backend is running successfully!", "model_loaded": model is not None}


@app.get("/health")
def health():
    _require_model()
    return {"status": "ok"}


@app.get("/model-info")
def model_info():
    _require_model()
    keys = ("model_name", "run_name", "dataset", "n_samples", "n_augmented", "n_relabeled",
            "trained_at", "metrics", "demo")
    info = {k: model_meta.get(k) for k in keys}
    info.update({"n_features": len(FEATURE_NAMES), "n_known_domains": len(KNOWN_DOMAINS),
                 "known_domains_top": config.KNOWN_DOMAINS_TOP,
                 "thresholds": {"medium": config.RISK_MEDIUM, "high": config.RISK_HIGH}})
    return info


@app.post("/predict", response_model=PredictionResponse)
def predict_url(request: URLRequest):
    # Never return a "result" when the model is missing: the client must not treat it as safe
    _require_model()
    start = time.perf_counter()
    try:
        url = normalize_url(request.url)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        features = extract_features(url)
        X = pd.DataFrame([features], columns=FEATURE_NAMES)
        p = float(model.predict_proba(X)[0][1])
        reasons = explain(model, features, url, model_meta.get("benign_reference", {}))
        anatomy = url_anatomy(url)
        known = match_known_domain(url, KNOWN_DOMAINS)
    except Exception:
        logger.exception("Prediction failed for %s", url)
        raise HTTPException(status_code=500, detail="Prediction failed")

    return PredictionResponse(
        url=url,
        prediction="Benign" if known else ("Malicious" if p >= 0.5 else "Benign"),
        risk_level="low" if known else risk_level(p),
        model_risk_level=risk_level(p),
        known_domain=known,
        confidence=max(p, 1 - p),
        malicious_probability=p,
        explanation=reasons,
        anatomy=anatomy,
        latency_ms=round((time.perf_counter() - start) * 1000, 2),
    )


@app.post("/predict/batch", response_model=List[BatchItem])
def predict_batch(request: BatchRequest):
    _require_model()
    items, valid, rows = [], [], []
    for raw in request.urls:
        try:
            url = normalize_url(raw)
            valid.append(len(items))
            rows.append(extract_features(url))
            items.append(BatchItem(url=url))
        except ValueError as e:
            items.append(BatchItem(url=raw, error=str(e)))
    if rows:
        probs = model.predict_proba(pd.DataFrame(rows, columns=FEATURE_NAMES))[:, 1]
        for idx, p in zip(valid, probs):
            p = float(p)
            known = match_known_domain(items[idx].url, KNOWN_DOMAINS)
            items[idx].prediction = "Benign" if known else ("Malicious" if p >= 0.5 else "Benign")
            items[idx].risk_level = "low" if known else risk_level(p)
            items[idx].model_risk_level = risk_level(p)
            items[idx].known_domain = known
            items[idx].malicious_probability = p
    return items
