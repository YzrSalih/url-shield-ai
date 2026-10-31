import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(APP_DIR)
PROJECT_DIR = os.path.dirname(BACKEND_DIR)

DATASET_DIR = os.getenv("DATASET_DIR", os.path.join(PROJECT_DIR, "dataset"))
MODELS_DIR = os.path.join(APP_DIR, "models")
REPORTS_DIR = os.getenv("REPORTS_DIR", os.path.join(PROJECT_DIR, "reports"))

MODEL_PATH = os.getenv("MODEL_PATH", os.path.join(MODELS_DIR, "url_model.pkl"))
MODEL_META_PATH = os.path.join(os.path.dirname(MODEL_PATH), "model_meta.json")

# Expected raw files inside dataset/
KAGGLE_FILE = "malicious_phish.csv"        # Kaggle: sid321axn/malicious-urls-dataset
URLHAUS_FILE = "urlhaus_recent.csv"        # https://urlhaus.abuse.ch/downloads/csv_recent/
OPENPHISH_FILE = "openphish_feed.txt"      # https://openphish.com/feed.txt
TRANCO_FILE = "tranco_top1m.csv"           # https://tranco-list.eu/top-1m.csv.zip

# Risk levels shown to the user (malicious probability)
RISK_MEDIUM = float(os.getenv("RISK_MEDIUM", 0.40))   # >= this: "Suspicious"
RISK_HIGH = float(os.getenv("RISK_HIGH", 0.70))       # >= this: "Malicious" (high risk)

# Known-domain allow-list: registered domains ranked 1..KNOWN_DOMAINS_TOP in the Tranco list are
# treated as legitimate when the URL is on the domain itself (not on a subdomain). 0 disables it.
KNOWN_DOMAINS_TOP = int(os.getenv("KNOWN_DOMAINS_TOP", 10000))
