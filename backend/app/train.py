"""
Trains and compares three classifiers on the Kaggle Malicious URLs dataset,
saves the best one for the API and writes thesis-ready reports to reports/.

Run (inside backend/):
    python -m app.train                          # final run: Tranco augmentation + label cleaning (default)
    python -m app.train --no-augment --no-clean  # "baseline": original Kaggle data only
    python -m app.train --no-clean               # "augmented": + Tranco domains, labels not cleaned
    python -m app.train --sample 50000  # quick run on a random subset
    python -m app.train --demo          # tiny built-in toy data (no dataset needed)
"""
import argparse
import json
import os
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app import config
from app.data import find_label_noise, load_kaggle
from app.utils.extractor import FEATURE_NAMES, extract_features

RANDOM_STATE = 42
# Tranco ranks 1..TRANCO_TEST_TOP are reserved for external testing and never used in training
TRANCO_TEST_TOP = 10000

DEMO_DATA = pd.DataFrame({
    "url": [
        "https://www.google.com", "https://github.com", "https://www.openai.com",
        "https://en.wikipedia.org/wiki/Phishing", "https://www.bbc.co.uk/news",
        "https://stackoverflow.com/questions/123/how-to-parse-url",
        "http://malicious-login-secure-bank.com/update",
        "http://192.168.1.1/login.php",
        "http://free-gift-card-claim-now.xyz/win",
        "http://paypal.com.account-verify.tk/webscr?cmd=login",
        "http://45.13.22.8/bins/mozi.arm7",
        "http://secure-update-billing.top/confirm/password.php?id=99812",
    ],
    "label": [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1],
})
DEMO_DATA["category"] = np.where(DEMO_DATA["label"] == 1, "malicious", "benign")


def build_models():
    return {
        "Logistic Regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=20, min_samples_leaf=5,
            class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE),
        "Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.1, class_weight="balanced",
            random_state=RANDOM_STATE),
    }


def featurize(urls) -> pd.DataFrame:
    t = time.time()
    rows = [extract_features(u) for u in urls]
    print(f"  extracted {len(FEATURE_NAMES)} features from {len(rows):,} URLs in {time.time() - t:.1f}s")
    return pd.DataFrame(rows, columns=FEATURE_NAMES)


def compute_metrics(y_true, y_pred, y_score) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, y_score) if len(set(y_true)) > 1 else float("nan"),
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "false_negative_rate": fn / (fn + tp) if (fn + tp) else 0.0,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def threshold_curve(y_true, scores) -> dict:
    """Confusion counts and metrics of the best model for decision thresholds 0.01 ... 0.99."""
    y_true = np.asarray(y_true)
    pos, neg = int((y_true == 1).sum()), int((y_true == 0).sum())
    rows = []
    for t in np.round(np.arange(0.01, 1.0, 0.01), 2):
        pred = scores >= t
        tp = int((pred & (y_true == 1)).sum())
        fp = int((pred & (y_true == 0)).sum())
        fn, tn = pos - tp, neg - fp
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / pos if pos else 0.0
        rows.append({"threshold": float(t), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                     "precision": prec, "recall": rec,
                     "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
                     "false_positive_rate": fp / neg if neg else 0.0})
    return {"n_positive": pos, "n_negative": neg, "points": rows}


def load_tranco_augmentation(n: int) -> pd.DataFrame:
    """
    Popular domains from Tranco (ranks > TRANCO_TEST_TOP) used as extra benign
    training data. Fixes the Kaggle bias where bare domains look malicious.
    """
    path = os.path.join(config.DATASET_DIR, config.TRANCO_FILE)
    if not os.path.exists(path):
        print(f"WARNING: {path} not found - training without augmentation "
              f"(run python -m app.download_data).")
        return pd.DataFrame(columns=["url", "label", "category"])
    tr = pd.read_csv(path, header=None, names=["rank", "url"])
    tr = tr[tr["rank"] > TRANCO_TEST_TOP]
    tr = tr.sample(min(n, len(tr)), random_state=RANDOM_STATE)
    return pd.DataFrame({"url": tr["url"].astype(str).tolist(), "label": 0,
                         "category": "benign (tranco)"})


def save_plots(results, y_test, best_name, best_model, X_test, reports_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # ROC curves (all models)
    fig, ax = plt.subplots(figsize=(6, 5))
    for name, r in results.items():
        fpr, tpr, _ = roc_curve(y_test, r["scores"])
        ax.plot(fpr, tpr, label=f"{name} (AUC = {r['metrics']['roc_auc']:.4f})")
    ax.plot([0, 1], [0, 1], "--", color="grey", linewidth=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves - Model Comparison")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(os.path.join(reports_dir, "roc_curves.png"), dpi=200)
    plt.close(fig)

    # Confusion matrix (best model)
    cm = np.array(results[best_name]["metrics"]["confusion_matrix"])
    fig, ax = plt.subplots(figsize=(5, 4.5))
    ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=12)
    ax.set_xticks([0, 1], ["Benign", "Malicious"])
    ax.set_yticks([0, 1], ["Benign", "Malicious"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix - {best_name}")
    fig.tight_layout()
    fig.savefig(os.path.join(reports_dir, "confusion_matrix.png"), dpi=200)
    plt.close(fig)

    # Permutation feature importance (best model, on a test subsample)
    n = min(len(X_test), 20000)
    idx = np.random.RandomState(RANDOM_STATE).choice(len(X_test), n, replace=False)
    imp = permutation_importance(best_model, X_test.iloc[idx], np.asarray(y_test)[idx],
                                 scoring="f1", n_repeats=5, random_state=RANDOM_STATE, n_jobs=-1)
    order = np.argsort(imp.importances_mean)[-15:]
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.barh(np.array(FEATURE_NAMES)[order], imp.importances_mean[order],
            xerr=imp.importances_std[order], color="#3b6fb6")
    ax.set_xlabel("Mean decrease in F1 score")
    ax.set_title(f"Top 15 Features (Permutation Importance) - {best_name}")
    fig.tight_layout()
    fig.savefig(os.path.join(reports_dir, "feature_importance.png"), dpi=200)
    plt.close(fig)
    return {FEATURE_NAMES[i]: float(imp.importances_mean[i]) for i in np.argsort(imp.importances_mean)[::-1]}


def write_markdown(path, info, results, best_name, per_category, importances):
    lines = [
        f"# Model Evaluation Results - {info['run_name']} run",
        "",
        f"- Dataset: {info['dataset']}",
        f"- Extra benign training data: {info['n_augmented']:,} Tranco domains (ranks > {TRANCO_TEST_TOP:,}, training set only)",
        f"- Label cleaning: {info['n_relabeled']:,} mislabelled 'benign' URLs relabelled as malicious",
        f"- Samples after cleaning: {info['n_samples']:,} "
        f"(benign {info['n_benign']:,} / malicious {info['n_malicious']:,})",
        f"- Train / test split: 80% / 20% stratified (test = {info['n_test']:,} URLs), random_state={RANDOM_STATE}",
        f"- Features: {len(FEATURE_NAMES)} lexical features (scheme and 'www.' removed to avoid leakage)",
        f"- Trained at: {info['trained_at']}",
        "",
        "## Model comparison (test set)",
        "",
        "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | Train time (s) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, r in results.items():
        m = r["metrics"]
        mark = " **(best)**" if name == best_name else ""
        lines.append(
            f"| {name}{mark} | {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | "
            f"{m['f1']:.4f} | {m['roc_auc']:.4f} | {m['false_positive_rate']:.4f} | "
            f"{m['false_negative_rate']:.4f} | {r['train_time']:.1f} |")
    if per_category:
        lines += ["", f"## Detection rate per category ({best_name})", "",
                  "| Category | Test URLs | Classified as malicious |", "|---|---|---|"]
        for cat, (n, rate) in per_category.items():
            lines.append(f"| {cat} | {n:,} | {rate:.2%} |")
    if importances:
        lines += ["", "## Most important features (permutation importance)", ""]
        for i, (f, v) in enumerate(list(importances.items())[:10], 1):
            lines.append(f"{i}. `{f}` - {v:.4f}")
    lines += ["", "Figures: `roc_curves.png`, `confusion_matrix.png`, `feature_importance.png`", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Train URL classifiers")
    parser.add_argument("--data", help="Path to malicious_phish.csv (default: dataset/)")
    parser.add_argument("--sample", type=int, help="Use a random subset of N URLs")
    parser.add_argument("--demo", action="store_true", help="Train on tiny built-in toy data")
    parser.add_argument("--augment", type=int, default=50000,
                        help="Number of Tranco benign domains added to the TRAINING set (default 50000)")
    parser.add_argument("--no-augment", action="store_true", help="Do not add Tranco domains")
    parser.add_argument("--no-clean", action="store_true",
                        help="Keep the original (noisy) Kaggle labels")
    args = parser.parse_args()

    if args.demo:
        df, dataset_name = DEMO_DATA.copy(), "built-in demo data (NOT for evaluation)"
    else:
        path = args.data or os.path.join(config.DATASET_DIR, config.KAGGLE_FILE)
        if not os.path.exists(path):
            raise SystemExit(f"Dataset not found: {path}\nDownload it (see app/download_data.py) "
                             f"or run `python -m app.train --demo` for a placeholder model.")
        print(f"Loading {path} ...")
        df, dataset_name = load_kaggle(path), "Kaggle Malicious URLs (malicious_phish.csv)"
    if args.sample and args.sample < len(df):
        df = df.sample(args.sample, random_state=RANDOM_STATE).reset_index(drop=True)

    print(f"Samples: {len(df):,}  (malicious ratio {df['label'].mean():.2%})")
    if "category" in df:
        print(df["category"].value_counts().to_string())
    X = featurize(df["url"].astype(str).tolist())
    # Plain NumPy arrays (pandas 3 uses Arrow-backed strings that sklearn cannot index)
    # .copy(): pandas 3 may return read-only views, and labels are modified below
    y = df["label"].to_numpy(dtype=np.int64).copy()
    categories = df["category"].astype(str).to_numpy(dtype=object).copy()

    # Label-noise correction: benign-labelled URLs with unambiguous phishing patterns
    clean = not (args.demo or args.no_clean)
    n_relabeled = 0
    if clean:
        noisy = find_label_noise(df, X)
        n_relabeled = int(noisy.sum())
        y[noisy] = 1
        categories[noisy] = "phishing (relabelled)"
        print(f"Label cleaning: {n_relabeled:,} benign-labelled URLs relabelled as malicious "
              f"({n_relabeled / max((df['label'] == 0).sum(), 1):.2%} of benign)")
        if n_relabeled:   # examples for manual inspection / the thesis appendix
            os.makedirs(config.REPORTS_DIR, exist_ok=True)
            df.loc[noisy, ["url", "category"]].sample(
                min(300, n_relabeled), random_state=RANDOM_STATE).to_csv(
                os.path.join(config.REPORTS_DIR, "relabelled_examples.csv"), index=False)

    test_size = 0.5 if args.demo else 0.2
    X_train, X_test, y_train, y_test, _, cat_test = train_test_split(
        X, y, categories, test_size=test_size, stratify=y, random_state=RANDOM_STATE)

    # Augmentation is added to the training set only, so test scores stay comparable
    augment = not (args.demo or args.no_augment) and args.augment > 0
    run_name = "demo" if args.demo else (
        {(False, False): "baseline", (True, False): "augmented",
         (False, True): "cleaned", (True, True): "final"}[(augment, clean)])
    n_augmented = 0
    if augment:
        aug = load_tranco_augmentation(args.augment)
        n_augmented = len(aug)
        if n_augmented:
            print(f"Adding {n_augmented:,} Tranco benign domains to the training set")
            X_train = pd.concat([X_train, featurize(aug["url"].tolist())], ignore_index=True)
            y_train = np.concatenate([y_train, np.zeros(n_augmented, dtype=np.int64)])
        else:
            run_name = "cleaned" if clean else "baseline"
    print(f"Run: {run_name}  (train {len(y_train):,} / test {len(y_test):,})")

    results = {}
    for name, model in build_models().items():
        print(f"\nTraining {name} ...")
        t = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t
        scores = model.predict_proba(X_test)[:, 1]
        preds = (scores >= 0.5).astype(int)
        metrics = compute_metrics(y_test, preds, scores)
        results[name] = {"model": model, "scores": scores, "preds": preds,
                         "metrics": metrics, "train_time": train_time}
        print(f"  F1={metrics['f1']:.4f}  ROC-AUC={metrics['roc_auc']:.4f}  "
              f"FPR={metrics['false_positive_rate']:.4f}  ({train_time:.1f}s)")

    best_name = max(results, key=lambda k: (results[k]["metrics"]["f1"], results[k]["metrics"]["roc_auc"]))
    best = results[best_name]
    print(f"\nBest model: {best_name}")

    per_category = {}
    for cat in sorted(set(cat_test)):
        mask = cat_test == cat
        per_category[cat] = (int(mask.sum()), float(best["preds"][mask].mean()))

    # Save model + metadata for the API
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    joblib.dump(best["model"], config.MODEL_PATH, compress=3)
    info = {
        "run_name": run_name, "n_augmented": int(n_augmented), "n_relabeled": n_relabeled,
        "dataset": dataset_name,
        "n_samples": int(len(df)), "n_benign": int((y == 0).sum()), "n_malicious": int((y == 1).sum()),
        "n_test": int(len(y_test)),
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    # Median feature values of benign training URLs (reference for explanations)
    benign_reference = X_train[np.asarray(y_train) == 0].median().astype(float).to_dict()
    meta = {"model_name": best_name, "feature_names": FEATURE_NAMES,
            "benign_reference": benign_reference,
            "sklearn_version": sklearn.__version__, "demo": args.demo,
            "metrics": {k: v for k, v in best["metrics"].items()}, **info}
    with open(config.MODEL_META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"Model saved to: {config.MODEL_PATH}")

    if args.demo:
        print("Demo model trained - reports are skipped for demo data.")
        return

    reports_dir = os.path.join(config.REPORTS_DIR, run_name)
    os.makedirs(reports_dir, exist_ok=True)
    print("Creating plots and reports ...")
    importances = save_plots(results, y_test, best_name, best["model"], X_test, reports_dir)
    with open(os.path.join(reports_dir, "threshold_curve.json"), "w", encoding="utf-8") as f:
        json.dump(threshold_curve(y_test, best["scores"]), f)
    with open(os.path.join(reports_dir, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump({"info": info, "best_model": best_name,
                   "models": {n: {**r["metrics"], "train_time_s": r["train_time"]} for n, r in results.items()},
                   "per_category_detection_rate": per_category,
                   "permutation_importance": importances}, f, indent=2)
    write_markdown(os.path.join(reports_dir, "results.md"), info, results,
                   best_name, per_category, importances)
    print(f"Reports written to: {reports_dir}")


if __name__ == "__main__":
    main()
