"""Web content / page retrieval. Walks the redirect chain and looks
for credential-harvesting forms, brand impersonation, and external
resource references.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

try:
    import lxml  # type: ignore  # noqa: F401
    BS_PARSER = "lxml"
except ImportError:  # pragma: no cover - fallback when lxml wheels are missing
    BS_PARSER = "html.parser"

import config
from collectors.base import BaseCollector
from core.models import ContentFeatures, IOC


BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "dhl", "fedex", "usps", "ups", "irs",
    "wellsfargo", "chase", "bankofamerica", "barclays", "hsbc",
    "office365", "outlook", "onedrive", "dropbox", "github",
    "stripe", "coinbase", "binance",
]

PASSWORD_PATTERNS = [
    re.compile(r'type=["\\\']?password["\\\']?', re.I),
    re.compile(r'name=["\\\']?(?:password|passwd|pass)["\\\']?', re.I),
]
CARD_PATTERNS = [
    re.compile(r'name=["\\\']?(?:cardnumber|card_number|ccnum|cc_number|cvv|cvc)["\\\']?', re.I),
]


class ContentCollector(BaseCollector):
    name = "content"
    description = "Web page content / redirect chain / brand impersonation"

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        url = context.get("final_url") or target
        if not url.startswith("http://") and not url.startswith("https://"):
            # Default to HTTPS when only a domain is supplied
            url = "https://" + url
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=False,
            )
        except Exception as exc:
            self._log_error(f"GET {url}", exc)
            return {"content": None}

        redirect_chain = [r.url for r in resp.history] + [resp.url]
        content = resp.content or b""
        content_type = resp.headers.get("Content-Type", "")
        size = len(content)

        soup = BeautifulSoup(content, BS_PARSER) if "html" in content_type.lower() or content else None
        title = ""
        meta_description = ""
        external_resources: List[str] = []
        brand_impersonation: List[str] = []
        has_password_field = False
        has_credit_card_field = False

        if soup is not None:
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
            desc = soup.find("meta", attrs={"name": "description"})
            if desc and desc.get("content"):
                meta_description = desc["content"].strip()
            for tag in soup.find_all(["a", "link", "script", "img", "iframe"]):
                src = tag.get("href") or tag.get("src")
                if not src:
                    continue
                if src.startswith("http"):
                    host = urlparse(src).netloc
                    if host and host != urlparse(url).netloc:
                        external_resources.append(host)
            lowered = (title + " " + meta_description + " " + url).lower()
            for brand in BRAND_KEYWORDS:
                if brand in lowered and not url.lower().endswith(f"{brand}.com"):
                    if brand in urlparse(url).netloc.lower():
                        continue
                    brand_impersonation.append(brand)
            html_lower = content.decode("utf-8", errors="ignore").lower()
            for pattern in PASSWORD_PATTERNS:
                if pattern.search(html_lower):
                    has_password_field = True
                    break
            for pattern in CARD_PATTERNS:
                if pattern.search(html_lower):
                    has_credit_card_field = True
                    break

        cookies = [c.name for c in resp.cookies]
        features = ContentFeatures(
            url=target,
            final_url=resp.url,
            status_code=resp.status_code,
            title=title,
            meta_description=meta_description,
            server=resp.headers.get("Server", ""),
            powered_by=resp.headers.get("X-Powered-By", ""),
            has_password_field=has_password_field,
            has_credit_card_field=has_credit_card_field,
            external_resources=sorted(set(external_resources))[:25],
            brand_impersonation=sorted(set(brand_impersonation)),
            redirect_chain=redirect_chain,
            response_size=size,
            content_type=content_type,
            cookies=cookies,
        )
        return {"content": features}

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        content = payload.get("content")
        if not content:
            return []
        iocs: List[IOC] = []
        malicious = content.has_password_field or content.has_credit_card_field or bool(content.brand_impersonation)
        if content.final_url:
            iocs.append(IOC(
                type="url_final",
                value=content.final_url,
                source=self.name,
                malicious=malicious,
                confidence=80 if malicious else 10,
                tags=content.brand_impersonation,
            ))
        for ext in content.external_resources:
            iocs.append(IOC(type="external_resource", value=ext, source=self.name))
        return iocs
