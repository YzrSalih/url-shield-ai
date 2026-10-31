from fastapi.testclient import TestClient

import app.main as main

client = TestClient(main.app)


def test_predict_returns_valid_label():
    if main.model is None:
        return  # model not trained in this environment
    r = client.post("/predict", json={"url": "https://github.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["prediction"] in {"Benign", "Malicious"}
    assert 0.5 <= body["confidence"] <= 1.0
    assert 0.0 <= body["malicious_probability"] <= 1.0


def test_invalid_url_returns_422():
    if main.model is None:
        return
    r = client.post("/predict", json={"url": "   "})
    assert r.status_code == 422


def test_missing_model_returns_503(monkeypatch):
    monkeypatch.setattr(main, "model", None)
    r = client.post("/predict", json={"url": "https://github.com"})
    assert r.status_code == 503


def test_predict_has_risk_level_and_latency():
    if main.model is None:
        return
    body = client.post("/predict", json={"url": "http://paypal.com.account-verify.tk/webscr?cmd=login"}).json()
    assert body["risk_level"] in {"low", "medium", "high"}
    assert body["latency_ms"] >= 0
    assert isinstance(body["explanation"], list)


def test_batch_handles_invalid_urls():
    if main.model is None:
        return
    r = client.post("/predict/batch", json={"urls": ["https://github.com", "   "]})
    assert r.status_code == 200
    items = r.json()
    assert items[0]["prediction"] in {"Benign", "Malicious"}
    assert items[1]["error"]
