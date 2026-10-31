# External Evaluation on Fresh Data

Model: Random Forest (trained 2026-10-31 12:14 UTC on Kaggle Malicious URLs (malicious_phish.csv), run: final)

URLs overlapping with the training dataset were removed.

| Source | URLs | Metric | Result |
|---|---|---|---|
| OpenPhish (phishing, live feed) | 300 | Detection rate | 46.67% |
| Tranco top-10k (benign domains) | 9,996 | Correctly benign (1 - FPR) | 95.63% |
