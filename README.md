# URL Shield AI

**Design and Implementation of a Machine Learning Based System for Malicious URL Detection**

Master's Thesis Project, Computer Science (MA Engineering), Akademia Finansów i Biznesu Vistula.

A FastAPI backend classifies a URL as `Benign` or `Malicious` from its lexical features
using a scikit-learn model, and a Streamlit frontend lets users analyze URLs interactively.

## Project structure

```
backend/
  app/
    main.py              # FastAPI service (/predict, /predict/batch, /model-info, /health)
    config.py            # Paths and risk thresholds
    data.py              # Dataset loading, cleaning, label-noise detection
    download_data.py     # Downloads Kaggle, URLhaus, OpenPhish, Tranco
    train.py             # Training, model comparison, reports
    evaluate_external.py # Test on fresh, unseen threat feeds
    explain.py           # Per-prediction explanations
    anatomy.py           # Splits a URL into parts with their risk signals
    utils/extractor.py   # URL normalization + 33 lexical features
    models/              # Trained model (created by train.py, not committed)
  tests/                 # pytest tests
  requirements.txt
frontend/
  app.py                 # Streamlit UI (analyze, batch, evaluation, system design)
  .streamlit/config.toml # UI theme
  requirements.txt
dataset/                 # Raw datasets (not committed)
reports/                 # Evaluation results and figures per run
```

## Setup

```bash
# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m app.download_data          # datasets -> dataset/
python -m app.train                  # final model (or --demo for a toy placeholder)
uvicorn app.main:app --reload        # http://127.0.0.1:8000  (docs: /docs)

# Frontend (new terminal)
cd frontend
pip install -r requirements.txt
streamlit run app.py
```

## Training on real data

1. Download all datasets (Kaggle training data via `kagglehub`, plus URLhaus, OpenPhish
   and Tranco for external testing) into `dataset/`:
   `python -m app.download_data`
2. Train and compare Logistic Regression, Random Forest and Gradient Boosting.
   Three runs reproduce the experiments of the thesis:

   ```bash
   python -m app.train --no-augment --no-clean && python -m app.evaluate_external  # baseline
   python -m app.train --no-clean && python -m app.evaluate_external               # + Tranco augmentation
   python -m app.train && python -m app.evaluate_external                          # final (+ label cleaning)
   ```

   The last run saves the model used by the API. Add `--sample 50000` for a quick run.

Results are written to `reports/<run>/`: `results.md`, `external_eval.md`, `metrics.json`,
`roc_curves.png`, `confusion_matrix.png`, `feature_importance.png`.

### Results (Random Forest, 33 features)

| Run | F1 | ROC-AUC | Precision | FPR | OpenPhish detection | Tranco top-10k correctly benign |
|---|---|---|---|---|---|---|
| Baseline (Kaggle only) | 0.834 | 0.956 | 0.813 | 0.098 | 46.3% | 0.0% |
| + Tranco augmentation | 0.807 | 0.945 | 0.774 | 0.122 | 53.3% | 94.5% |
| Final (+ label cleaning) | 0.823 | 0.947 | 0.804 | 0.114 | 46.7% | 95.6% |

**Methodology notes**

- 33 lexical features: lengths, character counts and ratios, entropy, subdomains, abused TLDs,
  suspicious keywords, URL shorteners, punycode, IP hosts, risky file extensions, brand
  impersonation and free-hosting platforms.
- **Leakage prevention:** the scheme (`http://`, `https://`) and `www.` are removed before feature
  extraction, because the Kaggle dataset stores most benign URLs without a scheme.
- **Bias mitigation:** a Kaggle-only model flags every popular bare domain (e.g. google.com) as
  malicious. 50,000 Tranco domains (ranks > 10,000) are added to the training set only;
  the Tranco top-10k is kept for external testing.
- **Label-noise correction:** 14,681 URLs (3.4% of the "benign" class) are obvious phishing kits,
  e.g. `paypal.com.us.cgi-bin.webscr...login...example.com.br`. They are relabelled as malicious
  (examples in `reports/relabelled_examples.csv`).
- Duplicates and URLs with conflicting labels are removed; the split is stratified 80/20.
  External evaluation removes any URL that also appears in the training data.
- **Explanations:** Random Forest predictions are decomposed along each tree's decision path
  (Saabas method), so the base rate plus all feature contributions equals the predicted probability.

## API

`POST /predict` with `{"url": "https://example.com"}` returns

```json
{"url": "https://example.com", "prediction": "Benign", "risk_level": "low", "confidence": 0.93,
 "malicious_probability": 0.07, "explanation": [...], "anatomy": [...], "latency_ms": 31.2}
```

Risk levels: `low` < 0.40 ≤ `medium` < 0.70 ≤ `high` (malicious probability).

Other endpoints: `POST /predict/batch` (up to 200 URLs), `GET /health`, `GET /model-info`.

| Status | Meaning |
|---|---|
| 200 | Classified successfully |
| 422 | URL is empty or cannot be parsed |
| 503 | Model is not loaded (train it first) |
| 500 | Unexpected prediction error |

## Configuration

| Variable | Default | Used by |
|---|---|---|
| `MODEL_PATH` | `backend/app/models/url_model.pkl` | backend |
| `BACKEND_URL` | `http://127.0.0.1:8000` | frontend |

## Tests

```bash
cd backend && pytest
```

