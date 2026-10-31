"""
Tests the trained model on FRESH, independent data that it has never seen:
  - URLhaus recent malware URLs + OpenPhish phishing feed  -> detection rate
  - Tranco top-10k popular domains                          -> false positive rate
URLs that also appear in the training dataset are removed first.

Run (inside backend/, after training):  python -m app.evaluate_external
"""
import json
import os

import joblib
import pandas as pd

from app import config
from app.data import load_kaggle, load_openphish, load_tranco, load_urlhaus
from app.utils.extractor import FEATURE_NAMES, extract_features

LOADERS = {
    "URLhaus (malware, recent)": (load_urlhaus, config.URLHAUS_FILE),
    "OpenPhish (phishing, live feed)": (load_openphish, config.OPENPHISH_FILE),
    "Tranco top-10k (benign domains)": (load_tranco, config.TRANCO_FILE),
}


def main():
    if not os.path.exists(config.MODEL_PATH):
        raise SystemExit("No trained model found. Run `python -m app.train` first.")
    model = joblib.load(config.MODEL_PATH)
    if getattr(model, "n_features_in_", len(FEATURE_NAMES)) != len(FEATURE_NAMES):
        raise SystemExit("The saved model was trained with an older feature set. "
                         "Run `python -m app.train` first.")
    meta = {}
    if os.path.exists(config.MODEL_META_PATH):
        with open(config.MODEL_META_PATH, encoding="utf-8") as f:
            meta = json.load(f)

    seen = set()
    kaggle_path = os.path.join(config.DATASET_DIR, config.KAGGLE_FILE)
    if os.path.exists(kaggle_path):
        seen = set(load_kaggle(kaggle_path)["url"].str.lower().str.replace(r"^https?://", "", regex=True))

    rows = []
    for name, (loader, filename) in LOADERS.items():
        path = os.path.join(config.DATASET_DIR, filename)
        if not os.path.exists(path):
            print(f"Skipping {name}: {path} not found (run python -m app.download_data)")
            continue
        df = loader(path)
        key = df["url"].str.lower().str.replace(r"^https?://", "", regex=True)
        before = len(df)
        df = df[~key.isin(seen)]
        if df.empty:
            print(f"Skipping {name}: no new URLs after removing overlap")
            continue
        X = pd.DataFrame([extract_features(u) for u in df["url"].astype(str).tolist()], columns=FEATURE_NAMES)
        pred = (model.predict_proba(X)[:, 1] >= 0.5).astype(int)
        label = int(df["label"].iloc[0])
        rate = float(pred.mean()) if label == 1 else float(1 - pred.mean())
        rows.append({"source": name, "urls": len(df), "removed_overlap": before - len(df),
                     "metric": "Detection rate" if label == 1 else "Correctly benign (1 - FPR)",
                     "value": rate})
        print(f"{name}: {len(df):,} URLs -> {rows[-1]['metric']}: {rate:.2%}")

    if not rows:
        raise SystemExit("No external data found in dataset/.")
    reports_dir = os.path.join(config.REPORTS_DIR, meta.get("run_name", ""))
    os.makedirs(reports_dir, exist_ok=True)
    with open(os.path.join(reports_dir, "external_eval.json"), "w", encoding="utf-8") as f:
        json.dump({"model": meta.get("model_name"), "results": rows}, f, indent=2)
    lines = ["# External Evaluation on Fresh Data", "",
             f"Model: {meta.get('model_name', 'unknown')} (trained {meta.get('trained_at', '?')} "
             f"on {meta.get('dataset', '?')}, run: {meta.get('run_name', '?')})", "",
             "URLs overlapping with the training dataset were removed.", "",
             "| Source | URLs | Metric | Result |", "|---|---|---|---|"]
    lines += [f"| {r['source']} | {r['urls']:,} | {r['metric']} | {r['value']:.2%} |" for r in rows]
    lines.append("")
    with open(os.path.join(reports_dir, "external_eval.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Report written to: {os.path.join(reports_dir, 'external_eval.md')}")


if __name__ == "__main__":
    main()
