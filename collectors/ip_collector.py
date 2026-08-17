"""IP-level reputation and geolocation.

* ip-api.com   free, no key needed for non-commercial use
* ipinfo.io    requires IPINFO_API_KEY for full precision
* AbuseIPDB    requires ABUSEIPDB_API_KEY
* ipwho.is     fallback IPv4/IPv6 lookup
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import config
from collectors.base import BaseCollector
from core.models import IOC, IpFeatures


class IpCollector(BaseCollector):
    name = "ip"
    description = "IP geolocation and reputation"

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        ip = context.get("ip") or target
        if not ip or ip.lower() in {"none", "unknown"}:
            return {"ip": None}

        features = IpFeatures(ip=ip)

        # ip-api.com
        resp = self.get(config.IPAPI_URL.format(ip=ip))
        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                data = {}
            if data.get("status") != "fail":
                features.country = data.get("country")
                features.region = data.get("regionName")
                features.city = data.get("city")
                features.isp = data.get("isp")
                features.org = data.get("org")
                features.asn = data.get("as")
                features.reverse_dns = data.get("reverse")

        # ipinfo.io (optional key)
        if config.IPINFO_API_KEY:
            resp = self.get(
                config.IPINFO_URL.format(ip=ip),
                headers={"Authorization": f"Bearer {config.IPINFO_API_KEY}"},
            )
            if resp is not None and resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    data = {}
                features.country = data.get("country", features.country)
                features.org = data.get("org", features.org)
                features.isp = data.get("org", features.isp)
                features.asn = data.get("org", features.asn)
                if "bogon" in (data.get("privacy") or []):
                    features.reputation = "suspicious"

        # AbuseIPDB (optional key)
        if config.ABUSEIPDB_API_KEY:
            resp = self.get(
                config.ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            if resp is not None and resp.status_code == 200:
                try:
                    data = resp.json().get("data", {})
                except ValueError:
                    data = {}
                features.abuse_confidence = data.get("abuseConfidenceScore")
                features.total_reports = data.get("totalReports")
                features.isp = data.get("isp", features.isp)
                features.country = data.get("countryCode", features.country)
                if (features.abuse_confidence or 0) >= 50:
                    features.reputation = "malicious"
                elif (features.abuse_confidence or 0) >= 20:
                    features.reputation = "suspicious"

        # Heuristic reputation finalisation
        if features.reputation == "unknown":
            if features.is_tor or features.is_proxy:
                features.reputation = "suspicious"
            else:
                features.reputation = "neutral"

        return {"ip": features}

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        ip: Optional[IpFeatures] = payload.get("ip")
        if not ip:
            return []
        malicious = ip.reputation in {"malicious", "suspicious"}
        confidence = {
            "malicious": 90,
            "suspicious": 65,
            "neutral": 20,
            "clean": 5,
        }.get(ip.reputation, 10)
        return [IOC(
            type="ip",
            value=ip.ip,
            source=self.name,
            malicious=malicious,
            confidence=confidence,
            tags=[ip.reputation, f"country:{ip.country or '??'}",
                  f"isp:{ip.isp or 'unknown'}"],
        )]
