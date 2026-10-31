# External Evaluation on Fresh Data

Model: Random Forest (trained 2026-10-31 12:05 UTC on Kaggle Malicious URLs (malicious_phish.csv), run: augmented)

URLs overlapping with the training dataset were removed.

| Source | URLs | Metric | Result |
|---|---|---|---|
| OpenPhish (phishing, live feed) | 300 | Detection rate | 53.33% |
| Tranco top-10k (benign domains) | 9,996 | Correctly benign (1 - FPR) | 94.48% |
