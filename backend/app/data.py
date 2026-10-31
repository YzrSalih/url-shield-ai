"""Loading and cleaning of the raw URL datasets."""
import os
import re

import numpy as np
import pandas as pd

from app import config


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.dropna(subset=["url"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 3]
    # Drop exact duplicates and URLs that appear with conflicting labels
    df = df.drop_duplicates(subset=["url", "label"])
    conflicting = df["url"].duplicated(keep=False)
    return df[~conflicting].reset_index(drop=True)


def load_kaggle(path: str = None) -> pd.DataFrame:
    """
    Kaggle 'Malicious URLs dataset' (malicious_phish.csv): columns url,type where
    type in {benign, phishing, defacement, malware}. Converted to a binary label
    (0 = benign, 1 = malicious); the original type is kept for per-class analysis.
    """
    path = path or os.path.join(config.DATASET_DIR, config.KAGGLE_FILE)
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]
    df = df.rename(columns={"type": "category"})
    df["category"] = df["category"].astype(str).str.strip().str.lower()
    df["label"] = (df["category"] != "benign").astype(int)
    return _clean(df[["url", "label", "category"]])


def load_urlhaus(path: str = None) -> pd.DataFrame:
    """URLhaus recent malware URLs (CSV with '#' comment lines)."""
    path = path or os.path.join(config.DATASET_DIR, config.URLHAUS_FILE)
    cols = ["id", "dateadded", "url", "url_status", "last_online", "threat",
            "tags", "urlhaus_link", "reporter"]
    df = pd.read_csv(path, comment="#", header=None, names=cols,
                     quotechar='"', skipinitialspace=True, on_bad_lines="skip")
    df["label"], df["category"], df["source"] = 1, "malware", "urlhaus"
    return _clean(df[["url", "label", "category", "source"]])


def load_openphish(path: str = None) -> pd.DataFrame:
    """OpenPhish community feed (one phishing URL per line)."""
    path = path or os.path.join(config.DATASET_DIR, config.OPENPHISH_FILE)
    with open(path, encoding="utf-8", errors="ignore") as f:
        urls = [line.strip() for line in f if line.strip()]
    df = pd.DataFrame({"url": urls})
    df["label"], df["category"], df["source"] = 1, "phishing", "openphish"
    return _clean(df)


def load_tranco(path: str = None, top_n: int = 10000) -> pd.DataFrame:
    """Tranco top sites list (rank,domain) - used as benign domains."""
    path = path or os.path.join(config.DATASET_DIR, config.TRANCO_FILE)
    df = pd.read_csv(path, header=None, names=["rank", "url"], nrows=top_n)
    df["label"], df["category"], df["source"] = 0, "benign", "tranco"
    return _clean(df[["url", "label", "category", "source"]])


# Strong phishing markers (PayPal-style kits, credential pages)
_PHISH_MARKERS = re.compile(
    r"webscr|cmd=_?login|signin|logon|verif|account.{0,20}(?:update|confirm|suspend|limit)"
    r"|secure.{0,15}(?:login|update)|banking|password", re.I)


def find_label_noise(df: pd.DataFrame, X: pd.DataFrame) -> np.ndarray:
    """
    Flags URLs labelled 'benign' that show unambiguous phishing patterns.
    The Kaggle dataset contains thousands of such mislabelled entries, e.g.
    'paypal.com.us.cgi-bin.webscr...login.submit.<random>.example.com.br'.
    Rule: (brand impersonation AND >=1 suspicious keyword)
          OR (phishing-kit marker AND >=2 suspicious keywords)
    """
    benign = df["label"].to_numpy() == 0
    brand = (X["brand_in_subdomain"].to_numpy() == 1) | (X["brand_in_path"].to_numpy() == 1)
    kw = X["suspicious_keyword_count"].to_numpy()
    marker = df["url"].astype(str).str.contains(_PHISH_MARKERS).to_numpy()
    return benign & ((brand & (kw >= 1)) | (marker & (kw >= 2)))
