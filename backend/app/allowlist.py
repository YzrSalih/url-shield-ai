"""
Known-domain allow-list, applied as a separate layer after the model.

The lexical model cannot verify who owns a domain, so genuine pages of very popular sites
(e.g. paypal.com/signin) can look like phishing. Registered domains from the top of the Tranco
ranking are therefore accepted as legitimate - but only when the URL is hosted on the domain
itself (or www.), never on a subdomain, and never for URL shorteners, free hosting or file/paste
platforms, where anyone can publish content. The model probability is still computed and returned.
"""
import os
from typing import Optional, Set
from urllib.parse import urlsplit

from app import config
from app.utils.extractor import FREE_HOSTING, SHORTENER_DOMAINS, registered_domain


# Popular platforms where anyone can publish files or pages under the main domain itself
# (e.g. pastebin.com/raw/..., angelfire.com/~user/...). They are never trusted as a whole.
USER_CONTENT_DOMAINS = {
    "pastebin.com", "angelfire.com", "freewebs.com", "tripod.com", "geocities.com", "1drv.ms",
    "dropbox.com", "mediafire.com", "sharepoint.com", "discord.com", "discordapp.com", "wetransfer.com",
    "telegra.ph", "hastebin.com", "paste.ee", "googleusercontent.com", "githubusercontent.com",
    "archive.org", "4shared.com", "box.com", "mega.nz", "sendspace.com", "zippyshare.com",
}


def _excluded(domain: str) -> bool:
    return (domain in SHORTENER_DOMAINS or domain in USER_CONTENT_DOMAINS
            or any(domain == d or domain.endswith("." + d) for d in FREE_HOSTING))


def load_known_domains(path: Optional[str] = None, top: Optional[int] = None) -> Set[str]:
    path = path or os.path.join(config.DATASET_DIR, config.TRANCO_FILE)
    top = config.KNOWN_DOMAINS_TOP if top is None else top
    known: Set[str] = set()
    if top <= 0 or not os.path.exists(path):
        return known
    with open(path, encoding="utf-8") as f:
        for line in f:
            rank, _, domain = line.strip().partition(",")
            try:
                if int(rank) > top:
                    break
            except ValueError:
                continue
            domain = domain.strip().lower()
            if domain and not _excluded(domain):
                known.add(domain)
    return known


def match_known_domain(url: str, known: Set[str]) -> Optional[str]:
    """Returns the matched domain if the URL is hosted directly on a known domain, else None."""
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if host.startswith("www."):
        host = host[4:]
    if host and host in known and registered_domain(host) == host and not _excluded(host):
        return host
    return None
