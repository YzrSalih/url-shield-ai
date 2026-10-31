"""
Local explanation of a single prediction.

1. Tree-based models (Random Forest): decision-path decomposition
   (Saabas, "treeinterpreter"). Every split on the path from the root to the leaf
   changes the predicted malicious probability; that change is credited to the
   feature used in the split. Averaged over all trees:
       P(malicious) = base rate + sum(feature contributions)   (exact)
2. Other models: perturbation analysis - each feature is replaced by the median
   value of benign training URLs and the change in probability is measured.
"""
from urllib.parse import urlparse

import numpy as np
import pandas as pd

from app.utils.extractor import FEATURE_NAMES, registered_domain

LABELS = {
    "url_length": "URL length",
    "hostname_length": "Hostname length",
    "path_length": "Path length",
    "query_length": "Query string length",
    "has_ip_host": "Raw IP address used as host",
    "has_port": "Explicit port number",
    "has_at": "'@' symbol in URL",
    "slash_count": "Number of '/'",
    "dot_count": "Number of '.'",
    "hyphen_count": "Number of '-'",
    "underscore_count": "Number of '_'",
    "question_count": "Number of '?'",
    "equals_count": "Number of '='",
    "ampersand_count": "Number of '&'",
    "percent_count": "Encoded characters ('%')",
    "digit_count": "Number of digits",
    "digit_ratio": "Share of digits",
    "letter_ratio": "Share of letters",
    "subdomain_count": "Number of subdomains",
    "hostname_hyphen_count": "Hyphens in hostname",
    "hostname_digit_count": "Digits in hostname",
    "tld_length": "Top-level domain",
    "suspicious_tld": "Frequently abused top-level domain",
    "is_shortener": "URL shortener service",
    "has_punycode": "Punycode (look-alike characters)",
    "has_double_slash_in_path": "'//' redirect pattern in path",
    "risky_extension": "Executable / archive file extension",
    "suspicious_keyword_count": "Suspicious keywords (login, verify, ...)",
    "url_entropy": "Randomness of the URL (entropy)",
    "hostname_entropy": "Randomness of the hostname (entropy)",
    "brand_in_subdomain": "Brand name outside the real domain",
    "brand_in_path": "Brand name in path on unrelated domain",
    "free_hosting": "Free hosting / site-builder platform",
}

BINARY = {n for n in FEATURE_NAMES if n.startswith(("has_", "is_")) or n in (
    "suspicious_tld", "risky_extension", "brand_in_subdomain", "brand_in_path", "free_hosting")}


def _display_value(name: str, value: float, url: str) -> str:
    if name in BINARY:
        return "yes" if value else "no"
    if name == "tld_length":
        host = (urlparse(url if "://" in url else "http://" + url).hostname or "")
        if not host or host.replace(".", "").isdigit():
            return "none (IP address)"
        return "." + host.rsplit(".", 1)[-1] if "." in host else "-"
    if name in ("digit_ratio", "letter_ratio"):
        return f"{value:.0%}"
    if name.endswith("entropy"):
        return f"{value:.2f}"
    return str(int(value))


def tree_contributions(model, features: list):
    """Exact per-feature contributions for a fitted RandomForestClassifier."""
    X = pd.DataFrame([features], columns=FEATURE_NAMES)
    cls = list(model.classes_).index(1)
    contrib = np.zeros(len(FEATURE_NAMES))
    bias = 0.0
    for est in model.estimators_:
        tree = est.tree_
        values = tree.value[:, 0, :]
        probs = values[:, cls] / values.sum(axis=1)
        path = est.decision_path(X.to_numpy(dtype=np.float32)).indices
        bias += probs[path[0]]
        for parent, child in zip(path[:-1], path[1:]):
            contrib[tree.feature[parent]] += probs[child] - probs[parent]
    n = len(model.estimators_)
    return bias / n, contrib / n


def _format(impacts, base, url, top_k):
    order = np.argsort(-np.abs(impacts))
    result = []
    for i in order[:top_k]:
        if abs(impacts[i]) < 0.005:
            continue
        name = FEATURE_NAMES[i]
        result.append({
            "feature": name,
            "label": LABELS.get(name, name),
            "value": _display_value(name, base[i], url),
            "impact": round(float(impacts[i]), 4),
            "direction": "increases risk" if impacts[i] > 0 else "decreases risk",
        })
    return result


def explain(model, features: list, url: str, reference: dict, top_k: int = 6) -> list:
    """Returns the top_k features with the largest effect on the prediction."""
    base = np.array(features, dtype=float)
    if hasattr(model, "estimators_") and hasattr(model.estimators_[0], "tree_"):
        _, impacts = tree_contributions(model, features)
        return _format(impacts, base, url, top_k)
    if not reference:
        return []
    rows = np.tile(base, (len(FEATURE_NAMES) + 1, 1))
    for i, name in enumerate(FEATURE_NAMES):
        rows[i + 1, i] = reference.get(name, base[i])
    probs = model.predict_proba(pd.DataFrame(rows, columns=FEATURE_NAMES))[:, 1]
    impacts = probs[0] - probs[1:]      # > 0: feature increases malicious probability
    return _format(impacts, base, url, top_k)


__all__ = ["explain", "LABELS", "registered_domain"]
