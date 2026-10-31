# Model Evaluation Results - baseline run

- Dataset: Kaggle Malicious URLs (malicious_phish.csv)
- Extra benign training data: 0 Tranco domains (ranks > 10,000, training set only)
- Label cleaning: 0 mislabelled 'benign' URLs relabelled as malicious
- Samples after cleaning: 641,110 (benign 428,074 / malicious 213,036)
- Train / test split: 80% / 20% stratified (test = 128,222 URLs), random_state=42
- Features: 33 lexical features (scheme and 'www.' removed to avoid leakage)
- Trained at: 2026-10-31 12:04 UTC

## Model comparison (test set)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | Train time (s) |
|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.7355 | 0.5926 | 0.6531 | 0.6214 | 0.8032 | 0.2235 | 0.3469 | 0.9 |
| Random Forest **(best)** | 0.8870 | 0.8131 | 0.8568 | 0.8344 | 0.9562 | 0.0980 | 0.1432 | 10.2 |
| Gradient Boosting | 0.8718 | 0.7787 | 0.8581 | 0.8164 | 0.9474 | 0.1214 | 0.1419 | 7.6 |

## Detection rate per category (Random Forest)

| Category | Test URLs | Classified as malicious |
|---|---|---|
| benign | 85,615 | 9.80% |
| defacement | 18,934 | 92.74% |
| malware | 4,842 | 96.63% |
| phishing | 18,831 | 75.76% |

## Most important features (permutation importance)

1. `tld_length` - 0.0960
2. `path_length` - 0.0630
3. `dot_count` - 0.0416
4. `slash_count` - 0.0395
5. `underscore_count` - 0.0286
6. `query_length` - 0.0225
7. `hostname_length` - 0.0218
8. `hostname_entropy` - 0.0199
9. `digit_count` - 0.0190
10. `url_length` - 0.0167

Figures: `roc_curves.png`, `confusion_matrix.png`, `feature_importance.png`
