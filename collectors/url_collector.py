"""URL structural analysis. No external API required.

Extracts lexical features of the URL that are commonly abused
in phishing campaigns, including suspicious keywords, IP-as-host,
excessive subdomains, punycode, and risky TLDs.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

import tldextract

import config
from collectors.base import BaseCollector
from core.models import IOC, UrlFeatures


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "security", "account",
    "update", "confirm", "bank", "password", "wallet", "paypal",
    "invoice", "support", "admin", "webscr", "cmd", "authenticate",
    "dropbox", "onedrive", "m365", "microsoft365", "office365",
    "appleid", "icloud", "google", "gmail", "facebook", "instagram",
    "whatsapp", "telegram", "netflix", "amazon", "dhl", "fedex",
    "usps", "irs", "tax", "reset", "unlock", "bonus", "free",
]

RISKY_TLDS = {
    "zip": 12, "review": 12, "country": 14, "kim": 10, "cricket": 10,
    "science": 10, "work": 10, "party": 10, "gq": 10, "cf": 10,
    "ml": 10, "tk": 10, "ga": 8, "xyz": 8, "top": 8, "click": 12,
    "loan": 10, "win": 10, "racing": 8, "trade": 10, "faith": 12,
    "stream": 8, "download": 8, "men": 8, "accountant": 10,
    "date": 8, "rest": 6, "support": 6, "center": 6,
}

BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "dhl", "fedex", "usps", "ups", "irs",
    "wellsfargo", "chase", "bankofamerica", "barclays", "hsbc",
    "office365", "outlook", "onedrive", "dropbox", "github",
]

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class UrlCollector(BaseCollector):
    name = "url"
    description = "Lexical analysis of the submitted URL"

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        parsed = urlparse(target)
        ext = tldextract.extract(target)
        netloc = parsed.netloc or ""
        hostname = netloc.split("@")[-1].split(":")[0]
        path = parsed.path or ""
        query = parsed.query or ""

        lower_url = target.lower()
        lower_host = hostname.lower()
        lower_path = path.lower()
        host_root = (ext.domain or "").lower()  # e.g. "paypal" in "paypal-secure.tk"

        # Suspicious keyword hits — but ignore matches that are the legitimate
        # second-level label of the host (so "google.com" doesn't match "google").
        suspicious_hits = []
        for k in SUSPICIOUS_KEYWORDS:
            if k in lower_path:
                suspicious_hits.append(k)
            elif k in lower_host and k not in host_root:
                suspicious_hits.append(k)
        brand_hits = [b for b in BRAND_KEYWORDS if b in lower_host and b not in host_root]

        subdomain_depth = max(0, len(ext.subdomain.split(".")) if ext.subdomain else 0)
        punycode = "xn--" in lower_host

        tld = (ext.suffix or "").lower()
        tld_risk = RISKY_TLDS.get(tld, 0)

        url_length = len(target)
        features = UrlFeatures(
            full_url=target,
            scheme=parsed.scheme or "",
            netloc=netloc,
            path=path,
            query=query,
            suspicious_keywords=suspicious_hits,
            has_ip_host=bool(IPV4_RE.match(hostname)),
            punycode=punycode,
            url_length=url_length,
            num_subdomains=subdomain_depth,
            tld=tld,
            tld_risk=tld_risk,
            risk_keywords=brand_hits,
        )
        return {"url": features}

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        url: UrlFeatures = payload.get("url")
        if not url:
            return []
        return [IOC(
            type="url",
            value=url.full_url,
            source=self.name,
            malicious=bool(url.risk_keywords or url.suspicious_keywords or url.has_ip_host),
            confidence=min(100, 20 + 10 * len(url.suspicious_keywords) + url.tld_risk),
            tags=url.suspicious_keywords + url.risk_keywords,
        )]
