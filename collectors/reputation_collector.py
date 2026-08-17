"""Reputation collectors that wrap external threat-intelligence providers.

All sources are optional and degrade gracefully when the corresponding
API key is not configured. Sources implemented:

* PhishTank        — https://checkurl.phishtank.com/checkurl/
* VirusTotal v3    — https://www.virustotal.com/api/v3/
* urlscan.io       — https://urlscan.io/docs/api/
"""
from __future__ import annotations

import base64
import time
from typing import Any, Dict, List

import config
from collectors.base import BaseCollector
from core.models import IOC, ReputationFeatures


class PhishTankCollector(BaseCollector):
    name = "phishtank"
    description = "PhishTank community-verified phishing URLs"

    def is_available(self) -> bool:
        return True

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        url = context.get("url") or target
        body = {
            "url": url,
            "format": "json",
        }
        if config.PHISHTANK_API_KEY:
            body["app_key"] = config.PHISHTANK_API_KEY
        resp = self.post(config.PHISHTANK_URL, data=body)
        empty = ReputationFeatures(target=url, sources=["phishtank"])
        if resp is None or resp.status_code != 200:
            return {"phishtank": empty}
        try:
            payload = resp.json()
        except ValueError:
            return {"phishtank": empty}
        results = payload.get("results", {})
        in_db = results.get("in_database", False)
        valid = results.get("valid", False)
        hit = bool(in_db and valid)
        return {"phishtank": ReputationFeatures(
            target=url,
            phishtank_hit=hit,
            phishtank_detail={
                "phish_id": results.get("phish_id"),
                "phish_detail_url": results.get("phish_detail_url"),
                "verified": valid,
                "verified_at": results.get("verified_at"),
            },
            sources=["phishtank"],
        )}

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        rep: ReputationFeatures = payload.get("phishtank")  # type: ignore[assignment]
        if not rep:
            return []
        return [IOC(
            type="reputation",
            value=rep.target,
            source=self.name,
            malicious=rep.phishtank_hit,
            confidence=95 if rep.phishtank_hit else 5,
            tags=["phishtank_hit"] if rep.phishtank_hit else [],
        )]


class VirusTotalCollector(BaseCollector):
    name = "virustotal"
    description = "VirusTotal multi-engine URL/IP/domain reputation"

    def is_available(self) -> bool:
        return bool(config.VIRUSTOTAL_API_KEY)

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if not config.VIRUSTOTAL_API_KEY:
            return {"virustotal": ReputationFeatures(target=target)}
        url = context.get("url") or target
        ip = context.get("ip")
        domain = context.get("domain")
        feat = ReputationFeatures(target=url)
        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

        # URL lookup
        lookup_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = self.get(f"{config.VIRUSTOTAL_URL}/{lookup_id}", headers=headers)
        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                feat.virustotal_malicious = stats.get("malicious", 0)
                feat.virustotal_suspicious = stats.get("suspicious", 0)
                feat.virustotal_harmless = stats.get("harmless", 0)
                feat.virustotal_undetected = stats.get("undetected", 0)
                feat.virustotal_total = sum(stats.values())
                feat.sources.append("virustotal_url")
            except ValueError:
                pass

        # IP lookup
        if ip:
            resp = self.get(config.VIRUSTOTAL_IP.format(ip=ip), headers=headers)
            if resp is not None and resp.status_code == 200:
                try:
                    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    feat.virustotal_malicious += stats.get("malicious", 0)
                    feat.virustotal_suspicious += stats.get("suspicious", 0)
                    feat.virustotal_total += sum(stats.values())
                    feat.sources.append("virustotal_ip")
                except ValueError:
                    pass

        # Domain lookup
        if domain:
            resp = self.get(config.VIRUSTOTAL_DOMAIN.format(domain=domain), headers=headers)
            if resp is not None and resp.status_code == 200:
                try:
                    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    feat.virustotal_malicious += stats.get("malicious", 0)
                    feat.virustotal_suspicious += stats.get("suspicious", 0)
                    feat.virustotal_total += sum(stats.values())
                    feat.sources.append("virustotal_domain")
                except ValueError:
                    pass

        return {"virustotal": feat}

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        rep: ReputationFeatures = payload.get("virustotal")  # type: ignore[assignment]
        if not rep:
            return []
        if rep.virustotal_total == 0:
            return []
        malicious = rep.virustotal_malicious > 0
        confidence = min(100, rep.virustotal_malicious * 4 + rep.virustotal_suspicious * 2)
        return [IOC(
            type="reputation",
            value=rep.target,
            source=self.name,
            malicious=malicious,
            confidence=confidence,
            tags=[
                f"vt:{rep.virustotal_malicious}/{rep.virustotal_total}",
                f"suspicious:{rep.virustotal_suspicious}",
            ] + rep.sources,
        )]


class UrlScanCollector(BaseCollector):
    name = "urlscan"
    description = "urlscan.io live submission and lookup"

    def is_available(self) -> bool:
        return bool(config.URLSCAN_API_KEY)

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if not config.URLSCAN_API_KEY:
            return {"urlscan": ReputationFeatures(target=target)}
        submit = context.get("submit", False)
        url = context.get("url") or target
        feat = ReputationFeatures(target=url)
        if not submit:
            return {"urlscan": feat}

        headers = {"API-Key": config.URLSCAN_API_KEY, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": "public"}
        resp = self.post(config.URLSCAN_SUBMIT, json=payload, headers=headers)
        if resp is None or resp.status_code != 200:
            return {"urlscan": feat}
        try:
            data = resp.json()
        except ValueError:
            return {"urlscan": feat}
        uuid = data.get("uuid")
        if not uuid:
            return {"urlscan": feat}
        feat.urlscan_uuid = uuid
        feat.urlscan_url = data.get("result")
        feat.sources.append("urlscan")

        # Poll for result
        for _ in range(6):
            time.sleep(5)
            r = self.get(config.URLSCAN_RESULT.format(uuid=uuid))
            if r is not None and r.status_code == 200:
                try:
                    body = r.json()
                except ValueError:
                    break
                verdicts = body.get("verdicts", {})
                overall = verdicts.get("overall", {})
                if overall.get("malicious") is True:
                    feat.virustotal_malicious = max(1, feat.virustotal_malicious)
                break
        return {"urlscan": feat}

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        rep: ReputationFeatures = payload.get("urlscan")  # type: ignore[assignment]
        if not rep or not rep.urlscan_uuid:
            return []
        return [IOC(
            type="reputation",
            value=rep.urlscan_url or rep.target,
            source=self.name,
            malicious=rep.virustotal_malicious > 0,
            confidence=50 if rep.virustotal_malicious > 0 else 10,
            tags=["urlscan"],
        )]
