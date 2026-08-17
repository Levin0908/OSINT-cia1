"""DNS enumeration using dnspython. Covers A/AAAA/MX/NS/TXT/SOA/CNAME
and detects the presence of SPF, DMARC and DKIM TXT records.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import dns.exception
import dns.rdatatype
import dns.resolver

import config
from collectors.base import BaseCollector
from core.models import DnsFeatures, IOC


class DnsCollector(BaseCollector):
    name = "dns"
    description = "DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) + email security"

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        domain = context.get("domain") or target
        if not domain or "." not in domain:
            return {"dns": None}

        features = DnsFeatures(domain=domain)
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        for rtype, attr in (("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"),
                            ("NS", "ns"), ("CNAME", "cname")):
            try:
                answers = resolver.resolve(domain, rtype)
                values = [r.to_text().rstrip(".") for r in answers]
                setattr(features, attr, values)
            except (dns.exception.DNSException, Exception):  # noqa: BLE001
                continue

        # TXT records split into SPF / DMARC / DKIM
        try:
            answers = resolver.resolve(domain, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                features.txt.append(txt)
                if txt.lower().startswith("v=spf1"):
                    features.has_spf = True
                    features.spf_record = txt
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            pass

        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = resolver.resolve(dmarc_domain, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.lower().startswith("v=dmarc1"):
                    features.has_dmarc = True
                    features.dmarc_record = txt
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            pass

        # DKIM selectors (common defaults)
        for selector in ("default", "google", "selector1", "k1", "mail", "s1"):
            try:
                answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for r in answers:
                    if "v=dkim1" in r.to_text().lower() or "k=rsa" in r.to_text().lower():
                        features.has_dkim = True
                        break
                if features.has_dkim:
                    break
            except (dns.exception.DNSException, Exception):  # noqa: BLE001
                continue

        # SOA
        try:
            answers = resolver.resolve(domain, "SOA")
            for r in answers:
                features.soa = r.to_text()
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            pass

        return {"dns": features}

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        dns: Optional[DnsFeatures] = payload.get("dns")
        if not dns:
            return []
        iocs: List[IOC] = []
        for ip in dns.a + dns.aaaa:
            iocs.append(IOC(type="dns_a", value=ip, source=self.name,
                            tags=["resolved"]))
        for mx in dns.mx:
            iocs.append(IOC(type="mx", value=mx, source=self.name,
                            tags=["mail_exchanger"]))
        for ns in dns.ns:
            iocs.append(IOC(type="ns", value=ns, source=self.name))
        return iocs
