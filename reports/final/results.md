# Model Evaluation Results - final run

- Dataset: Kaggle Malicious URLs (malicious_phish.csv)
- Extra benign training data: 50,000 Tranco domains (ranks > 10,000, training set only)
- Label cleaning: 14,681 mislabelled 'benign' URLs relabelled as malicious
- Samples after cleaning: 641,110 (benign 413,393 / malicious 227,717)
- Train / test split: 80% / 20% stratified (test = 128,222 URLs), random_state=42
- Features: 33 lexical features (scheme and 'www.' removed to avoid leakage)
- Trained at: 2026-10-31 12:14 UTC

## Model comparison (test set)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | Train time (s) |
|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.7700 | 0.6950 | 0.6282 | 0.6600 | 0.8149 | 0.1518 | 0.3718 | 0.8 |
| Random Forest **(best)** | 0.8709 | 0.8036 | 0.8426 | 0.8226 | 0.9466 | 0.1135 | 0.1574 | 9.9 |
| Gradient Boosting | 0.8581 | 0.7787 | 0.8388 | 0.8076 | 0.9393 | 0.1313 | 0.1612 | 6.9 |

## Detection rate per category (Random Forest)

| Category | Test URLs | Classified as malicious |
|---|---|---|
| benign | 82,679 | 11.35% |
| defacement | 19,073 | 93.42% |
| malware | 4,775 | 94.79% |
| phishing | 18,703 | 69.81% |
| phishing (relabelled) | 2,992 | 99.43% |

## Most important features (permutation importance)

1. `tld_length` - 0.0958
2. `path_length` - 0.0424
3. `dot_count` - 0.0387
4. `slash_count` - 0.0339
5. `underscore_count` - 0.0278
6. `hostname_length` - 0.0225
7. `hostname_entropy` - 0.0217
8. `suspicious_keyword_count` - 0.0181
9. `ampersand_count` - 0.0163
10. `letter_ratio` - 0.0129

Figures: `roc_curves.png`, `confusion_matrix.png`, `feature_importance.png`
