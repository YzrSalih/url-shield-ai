"""
Downloads all data sources into dataset/:
  - Kaggle Malicious URLs dataset (training data) via kagglehub
  - URLhaus, OpenPhish, Tranco (fresh external test data)

Run (inside backend/):  python -m app.download_data
"""
import glob
import io
import os
import shutil
import urllib.request
import zipfile

from app import config

SOURCES = {
    config.URLHAUS_FILE: "https://urlhaus.abuse.ch/downloads/csv_recent/",
    config.OPENPHISH_FILE: "https://openphish.com/feed.txt",
    config.TRANCO_FILE: "https://tranco-list.eu/top-1m.csv.zip",
}
HEADERS = {"User-Agent": "url-shield-ai/1.0 (academic research)"}
KAGGLE_DATASET = "sid321axn/malicious-urls-dataset"


def download_kaggle():
    target = os.path.join(config.DATASET_DIR, config.KAGGLE_FILE)
    if os.path.exists(target):
        print(f"Kaggle dataset already present: {target}")
        return
    try:
        import kagglehub
        print(f"Downloading Kaggle dataset {KAGGLE_DATASET} ...")
        cache_dir = kagglehub.dataset_download(KAGGLE_DATASET)
        matches = glob.glob(os.path.join(cache_dir, "**", config.KAGGLE_FILE), recursive=True)
        if not matches:
            raise FileNotFoundError(f"{config.KAGGLE_FILE} not found in {cache_dir}")
        shutil.copy(matches[0], target)
        print(f"  saved -> {target} ({os.path.getsize(target) / 1e6:.1f} MB)")
    except Exception as e:
        print(f"  FAILED: {e}")
        print(f"  Download it manually from https://www.kaggle.com/datasets/{KAGGLE_DATASET}")
        print(f"  and save it as {target}")


def fetch(url: str) -> bytes:
    headers = dict(HEADERS)
    # abuse.ch (URLhaus) requires a free Auth-Key: https://auth.abuse.ch/
    if "abuse.ch" in url and os.getenv("URLHAUS_AUTH_KEY"):
        headers["Auth-Key"] = os.environ["URLHAUS_AUTH_KEY"]
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def main():
    os.makedirs(config.DATASET_DIR, exist_ok=True)
    download_kaggle()
    for filename, url in SOURCES.items():
        target = os.path.join(config.DATASET_DIR, filename)
        try:
            print(f"Downloading {url} ...")
            data = fetch(url)
            if url.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    data = z.read(z.namelist()[0])
            with open(target, "wb") as f:
                f.write(data)
            print(f"  saved -> {target} ({len(data) / 1e6:.1f} MB)")
        except Exception as e:
            print(f"  FAILED: {e}. You can download it manually and save it as {target}")
            if "abuse.ch" in url:
                print("  (URLhaus needs a free Auth-Key from https://auth.abuse.ch/ -> "
                      "export URLHAUS_AUTH_KEY=... and run again. This source is optional.)")
    print("\nDone. Files in dataset/:", ", ".join(sorted(os.listdir(config.DATASET_DIR))))


if __name__ == "__main__":
    main()
