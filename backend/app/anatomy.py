"""
Splits a URL into its structural parts and attaches the signals that the
feature extractor found in each part. Used by the UI to show *where* in the
URL the risk comes from. Pure string analysis - the URL is never requested.
"""
from urllib.parse import urlparse

from app.utils.extractor import (BRANDS, FEATURE_NAMES, FREE_HOSTING, IPV4_PATTERN, RISKY_EXTENSIONS,
                                 SHORTENER_DOMAINS, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS,
                                 _mentions_brand, extract_features, registered_domain)


def _keywords(text: str) -> list:
    t = text.lower()
    return [k for k in SUSPICIOUS_KEYWORDS if k in t]


def _is_brand_site(host: str) -> bool:
    """True when the registered domain itself belongs to a known brand (e.g. paypal.com)."""
    return bool(host) and registered_domain(host).split(".")[0] in BRANDS


def _part(kind, text, notes, level=None):
    if level is None:
        level = "flag" if any(n[1] == "flag" for n in notes) else ("warn" if notes else "ok")
    return {"part": kind, "text": text, "level": level,
            "notes": [n[0] for n in notes] or ["nothing unusual"]}


def url_anatomy(url: str) -> list:
    f = dict(zip(FEATURE_NAMES, extract_features(url)))
    p = urlparse(url if "://" in url else "http://" + url)
    raw_host = p.hostname or ""
    host = raw_host[4:] if raw_host.startswith("www.") else raw_host
    parts = [_part("scheme", f"{p.scheme}://", [("not used by the model (dataset leakage)", "info")], "muted")]
    if raw_host.startswith("www."):
        parts.append(_part("www", "www.", [("ignored", "info")], "muted"))

    if IPV4_PATTERN.match(host):
        parts.append(_part("host", host, [("raw IP address instead of a domain name", "flag")]))
    else:
        reg = registered_domain(host)
        sub = host[: len(host) - len(reg)] if reg and host.endswith(reg) else ""
        name, _, tld = reg.partition(".")
        if sub:
            notes = []
            if f["brand_in_subdomain"] and _mentions_brand(sub):
                notes.append(("brand name outside the real domain", "flag"))
            kw = _keywords(sub)
            if kw:
                notes.append(("keywords: " + ", ".join(kw[:3]), "warn"))
            if f["subdomain_count"] >= 3:
                notes.append((f"{f['subdomain_count']} subdomain levels", "warn"))
            if any(ch.isdigit() for ch in sub) and sum(ch.isdigit() for ch in sub) >= 4:
                notes.append(("many digits", "warn"))
            parts.append(_part("subdomain", sub, notes))
        notes = []
        if f["brand_in_subdomain"] and _mentions_brand(name):
            notes.append(("imitates a known brand", "flag"))
        kw = [] if name in BRANDS else _keywords(name)   # the brand's own domain is fine
        if kw:
            notes.append(("keywords: " + ", ".join(kw[:3]), "warn"))
        if name.count("-") >= 1:
            notes.append((f"{name.count('-')} hyphen(s)", "warn"))
        if f["has_punycode"]:
            notes.append(("punycode look-alike characters", "flag"))
        if f["is_shortener"]:
            notes.append(("URL shortener hides the destination", "warn"))
        if f["free_hosting"]:
            notes.append(("free hosting platform", "warn"))
        parts.append(_part("domain", name, notes))
        if tld:
            notes = [("frequently abused top-level domain", "flag")] if f["suspicious_tld"] else []
            parts.append(_part("tld", "." + tld, notes))
    if p.port:
        parts.append(_part("port", f":{p.port}", [("explicit port number", "warn")]))

    if p.path and p.path != "/":
        notes = []
        if f["risky_extension"]:
            notes.append(("executable or archive download", "flag"))
        if f["brand_in_path"] and _mentions_brand(p.path):
            notes.append(("brand name on an unrelated site", "flag"))
        if "webscr" in p.path.lower() and not _is_brand_site(host):
            notes.append(("known PayPal phishing-kit path", "flag"))
        kw = [] if _is_brand_site(host) else [k for k in _keywords(p.path) if k != "webscr"]
        if kw:
            notes.append(("keywords: " + ", ".join(kw[:3]), "warn"))
        if f["has_double_slash_in_path"]:
            notes.append(("'//' redirect pattern", "warn"))
        if len(p.path) > 60:
            notes.append((f"long path ({len(p.path)} chars)", "warn"))
        parts.append(_part("path", p.path, notes))
    if p.query:
        notes = []
        kw = [] if _is_brand_site(host) else _keywords(p.query)
        if kw:
            notes.append(("keywords: " + ", ".join(kw[:3]), "warn"))
        if len(p.query) > 80:
            notes.append((f"long query ({len(p.query)} chars)", "warn"))
        parts.append(_part("query", "?" + p.query, notes))
    return parts
