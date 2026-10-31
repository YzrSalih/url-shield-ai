"""
Lexical feature extraction for malicious URL detection.

Design note (methodology): features are computed on the URL *without* its scheme
(http/https) and without a leading 'www.'. Many public datasets store benign URLs
without a scheme while malicious ones include 'http://', so keeping the scheme
would let the model "cheat" by learning the dataset's formatting instead of
real URL characteristics (data leakage).
"""
import math
import re
from collections import Counter
from urllib.parse import urlparse

IPV4_PATTERN = re.compile(
    r'^(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])$'
)

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "logon", "verify", "verification", "account", "update",
    "secure", "security", "bank", "banking", "confirm", "password", "passwd",
    "webscr", "ebayisapi", "paypal", "wallet", "free", "bonus", "gift", "lucky",
    "admin", "invoice", "payment", "unlock", "suspend", "billing",
)

SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "s.id", "t.ly", "v.gd", "qrco.de", "lnkd.in",
}

# TLDs frequently abused in phishing/malware campaigns (Spamhaus / Interisle reports)
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "link",
    "work", "support", "country", "kim", "loan", "men", "date", "racing",
    "review", "stream", "download", "win", "bid", "icu", "buzz", "rest", "cam",
    "online", "site", "live", "shop", "fit", "monster", "cyou", "sbs", "cfd",
}

# Frequently impersonated brands (APWG / phishing trend reports)
BRANDS = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "hotmail",
    "google", "gmail", "amazon", "facebook", "instagram", "whatsapp", "netflix",
    "linkedin", "dropbox", "adobe", "docusign", "chase", "wellsfargo",
    "bankofamerica", "citibank", "hsbc", "santander", "dhl", "fedex", "ups",
    "usps", "ebay", "yahoo", "steam", "binance", "coinbase", "metamask",
    "blockchain", "allegro", "inpost", "mbank", "revolut", "spotify", "twitter",
)

# Free hosting / site builder platforms often abused to host phishing pages
FREE_HOSTING = (
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com",
    "web.app", "blogspot.com", "github.io", "netlify.app", "vercel.app",
    "herokuapp.com", "glitch.me", "repl.co", "sites.google.com", "ngrok.io",
    "pages.dev", "workers.dev", "godaddysites.com", "square.site", "webflow.io",
    "duckdns.org", "no-ip.com", "freenom.com",
)

# Second-level public suffixes, so 'bbc.co.uk' -> registered domain 'bbc.co.uk'
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}

RISKY_EXTENSIONS = (
    ".exe", ".apk", ".bin", ".sh", ".scr", ".bat", ".dll", ".jar", ".msi",
    ".zip", ".rar", ".7z", ".js", ".vbs", ".ps1", ".doc", ".xls", ".i", ".mips", ".arm7",
)

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "has_ip_host",
    "has_port",
    "has_at",
    "slash_count",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "question_count",
    "equals_count",
    "ampersand_count",
    "percent_count",
    "digit_count",
    "digit_ratio",
    "letter_ratio",
    "subdomain_count",
    "hostname_hyphen_count",
    "hostname_digit_count",
    "tld_length",
    "suspicious_tld",
    "is_shortener",
    "has_punycode",
    "has_double_slash_in_path",
    "risky_extension",
    "suspicious_keyword_count",
    "url_entropy",
    "hostname_entropy",
    "brand_in_subdomain",
    "brand_in_path",
    "free_hosting",
]


def registered_domain(hostname: str) -> str:
    """Approximate registrable domain: 'login.paypal.com.evil.tk' -> 'evil.tk'."""
    labels = [l for l in hostname.split(".") if l]
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def normalize_url(url: str) -> str:
    """
    Strips whitespace and adds a scheme when it is missing, so that
    'example.com/login' is parsed the same way as 'http://example.com/login'.
    Raises ValueError for empty / unparsable input.
    """
    url = (url or "").strip()
    if not url:
        raise ValueError("URL is empty")
    if "://" not in url:
        url = "http://" + url
    try:
        hostname = urlparse(url).hostname
    except ValueError as e:
        raise ValueError(f"Could not parse URL: {url!r}") from e
    if not hostname:
        raise ValueError(f"Could not parse a hostname from URL: {url!r}")
    return url


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _mentions_brand(text: str) -> bool:
    """
    True if a known brand appears as a token ('paypal-login' -> paypal).
    Long brand names (>= 6 chars) may also appear inside a token ('mypaypal'),
    short ones (ups, dhl, chase, apple) must match a whole token to avoid
    false hits like "groups", "purchase" or "pineapple".
    """
    tokens = [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]
    for b in BRANDS:
        for t in tokens:
            if t == b or (len(b) >= 6 and b in t):
                return True
    return False


def _strip_scheme_and_www(url: str) -> str:
    url = url.strip()
    url = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', url)
    if url.lower().startswith("www."):
        url = url[4:]
    return url


def extract_features(url: str) -> list:
    """
    Extracts lexical features from a URL. The order of the returned list
    matches FEATURE_NAMES. Works with or without a scheme.
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        path, query = parsed.path or "", parsed.query or ""
    except ValueError:  # malformed (e.g. bad port / IPv6) - fall back to raw text
        hostname, port, path, query = "", None, "", ""

    if hostname.startswith("www."):
        hostname = hostname[4:]
    body = _strip_scheme_and_www(url)       # URL text used for counting features
    lower = body.lower()

    n = len(body) or 1
    digits = sum(ch.isdigit() for ch in body)
    letters = sum(ch.isalpha() for ch in body)

    is_ip = bool(IPV4_PATTERN.match(hostname))
    labels = hostname.split(".") if hostname else []
    tld = "" if is_ip or len(labels) < 2 else labels[-1]

    # Brand impersonation: brand name used outside the real registered domain
    reg = "" if is_ip else registered_domain(hostname)
    reg_name = reg.split(".")[0] if reg else ""
    outside_reg = hostname[: max(len(hostname) - len(reg), 0)]   # subdomain part
    brand_owner = reg_name in BRANDS
    brand_in_subdomain = int(not brand_owner and (
        _mentions_brand(outside_reg) or (_mentions_brand(reg_name) and reg_name not in BRANDS)))
    brand_in_path = int(not brand_owner and _mentions_brand(path + " " + query))
    free_hosting = int(any(hostname == d or hostname.endswith("." + d) for d in FREE_HOSTING))

    features = [
        len(body),                                              # url_length
        len(hostname),                                          # hostname_length
        len(path),                                              # path_length
        len(query),                                             # query_length
        int(is_ip),                                             # has_ip_host
        int(port is not None),                                  # has_port
        int("@" in body),                                       # has_at
        body.count("/"),                                        # slash_count
        body.count("."),                                        # dot_count
        body.count("-"),                                        # hyphen_count
        body.count("_"),                                        # underscore_count
        body.count("?"),                                        # question_count
        body.count("="),                                        # equals_count
        body.count("&"),                                        # ampersand_count
        body.count("%"),                                        # percent_count
        digits,                                                 # digit_count
        digits / n,                                             # digit_ratio
        letters / n,                                            # letter_ratio
        0 if is_ip else max(len(labels) - 2, 0),                # subdomain_count
        hostname.count("-"),                                    # hostname_hyphen_count
        sum(ch.isdigit() for ch in hostname),                   # hostname_digit_count
        len(tld),                                               # tld_length
        int(tld in SUSPICIOUS_TLDS),                            # suspicious_tld
        int(hostname in SHORTENER_DOMAINS),                     # is_shortener
        int("xn--" in hostname),                                # has_punycode
        int("//" in path),                                      # has_double_slash_in_path
        int(path.lower().endswith(RISKY_EXTENSIONS)),           # risky_extension
        sum(lower.count(k) for k in SUSPICIOUS_KEYWORDS),       # suspicious_keyword_count
        _entropy(body),                                         # url_entropy
        _entropy(hostname),                                     # hostname_entropy
        brand_in_subdomain,                                     # brand_in_subdomain
        brand_in_path,                                          # brand_in_path
        free_hosting,                                           # free_hosting
    ]
    return features
