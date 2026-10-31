# Model Evaluation Results - augmented run

- Dataset: Kaggle Malicious URLs (malicious_phish.csv)
- Extra benign training data: 50,000 Tranco domains (ranks > 10,000, training set only)
- Label cleaning: 0 mislabelled 'benign' URLs relabelled as malicious
- Samples after cleaning: 641,110 (benign 428,074 / malicious 213,036)
- Train / test split: 80% / 20% stratified (test = 128,222 URLs), random_state=42
- Features: 33 lexical features (scheme and 'www.' removed to avoid leakage)
- Trained at: 2026-10-31 12:05 UTC

## Model comparison (test set)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | Train time (s) |
|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.7506 | 0.6325 | 0.5957 | 0.6135 | 0.7876 | 0.1722 | 0.4043 | 0.6 |
| Random Forest **(best)** | 0.8660 | 0.7743 | 0.8424 | 0.8069 | 0.9445 | 0.1222 | 0.1576 | 11.4 |
| Gradient Boosting | 0.8497 | 0.7444 | 0.8344 | 0.7868 | 0.9331 | 0.1426 | 0.1656 | 8.0 |

## Detection rate per category (Random Forest)

| Category | Test URLs | Classified as malicious |
|---|---|---|
| benign | 85,615 | 12.22% |
| defacement | 18,934 | 94.73% |
| malware | 4,842 | 95.02% |
| phishing | 18,831 | 70.91% |

## Most important features (permutation importance)

1. `tld_length` - 0.0914
2. `path_length` - 0.0499
3. `dot_count` - 0.0418
4. `slash_count` - 0.0387
5. `underscore_count` - 0.0322
6. `hostname_entropy` - 0.0245
7. `hostname_length` - 0.0239
8. `query_length` - 0.0218
9. `letter_ratio` - 0.0170
10. `digit_count` - 0.0138

Figures: `roc_curves.png`, `confusion_matrix.png`, `feature_importance.png`
