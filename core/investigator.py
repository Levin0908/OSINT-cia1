"""Investigation orchestrator.

This module is the only one collectors need to know about. It accepts
a target string, runs every collector in the right order, threads
results into a single :class:`InvestigationResult`, scores it,
correlates findings, and returns the report.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import tldextract

from collectors.base import BaseCollector
from collectors.content_collector import ContentCollector
from collectors.dns_collector import DnsCollector
from collectors.domain_collector import DomainCollector
from collectors.ip_collector import IpCollector
from collectors.reputation_collector import (
    PhishTankCollector,
    UrlScanCollector,
    VirusTotalCollector,
)
from collectors.ssl_collector import SslCollector
from collectors.url_collector import UrlCollector
from core.correlator import correlate
from core.database import Database
from core.models import InvestigationRequest, InvestigationResult
from core.scoring import compute_score

logger = logging.getLogger(__name__)


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def _hostname_from(target: str) -> str:
    if _is_url(target):
        from urllib.parse import urlparse
        return (urlparse(target).hostname or "").lower()
    return target.lower()


def _extract_domain(target: str) -> str:
    """Best-effort registered domain name."""
    if _is_url(target):
        from urllib.parse import urlparse
        host = urlparse(target).hostname or ""
    else:
        host = target
    ext = tldextract.extract(host)
    return ext.registered_domain or host


def _resolve_ip(domain: str) -> Optional[str]:
    if not domain:
        return None
    try:
        import socket
        return socket.gethostbyname(domain)
    except Exception:
        return None


class Investigator:
    """Coordinates the OSINT collection pipeline."""

    def __init__(self, db: Optional[Database] = None) -> None:
        self.db = db or Database()
        self.errors: List[str] = []
        self.collectors: List[BaseCollector] = [
            UrlCollector(),
            DomainCollector(),
            DnsCollector(),
            IpCollector(),
            SslCollector(),
            ContentCollector(),
            PhishTankCollector(),
            VirusTotalCollector(),
            UrlScanCollector(),
        ]

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        target = request.target.strip()
        is_url = _is_url(target)
        hostname = _hostname_from(target)
        domain = _extract_domain(target)

        result = InvestigationResult(target=target, is_url=is_url)
        shared: Dict[str, Any] = {
            "url": target,
            "hostname": hostname,
            "domain": domain,
            "ip": None,
            "submit": request.submit_urlscan,
        }

        # Step 1: passive collectors (lightweight, no network to the target)
        for collector in (self.collectors[0], self.collectors[1], self.collectors[2]):
            self._run(collector, target, shared, result)

        # Step 2: resolve IP if we have a domain
        ip = _resolve_ip(domain) if domain else None
        shared["ip"] = ip

        # Step 3: IP + SSL + content + reputation
        # Only run SSL if the hostname is reachable on HTTPS
        if request.scan and hostname:
            for collector in (self.collectors[3], self.collectors[4], self.collectors[5]):
                self._run(collector, target, shared, result)
        elif ip:
            self._run(self.collectors[3], target, shared, result)

        # Step 4: external reputation
        for collector in (self.collectors[6], self.collectors[7], self.collectors[8]):
            if collector.is_available():
                self._run(collector, target, shared, result)

        # Step 5: score + correlate
        compute_score(result)
        result.correlations = correlate(result)
        result.errors = self._collect_errors()

        # Step 6: persist
        try:
            result.id = self.db.save(result)
        except Exception as exc:
            logger.warning("DB save failed: %s", exc)
        return result

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _run(self, collector: BaseCollector, target: str, shared: Dict[str, Any],
             result: InvestigationResult) -> None:
        try:
            payload = collector.collect(target, shared)
        except Exception as exc:
            logger.exception("collector %s crashed", collector.name)
            self.errors.append(f"{collector.name}: {exc}")
            return

        for key, value in payload.items():
            if value is None:
                continue
            if key in {"phishtank", "virustotal", "urlscan"}:
                self._merge_reputation(result, value)
                continue
            setattr(result, key, value)

        try:
            iocs = collector.extract_iocs(payload)
            result.iocs.extend(iocs)
        except Exception as exc:
            logger.warning("ioc extraction failed for %s: %s", collector.name, exc)

    def _merge_reputation(self, result: InvestigationResult,
                          rep: Any) -> None:
        """Merge a new reputation result into the aggregate."""
        from core.models import ReputationFeatures
        if not isinstance(rep, ReputationFeatures):
            return
        if result.reputation is None:
            result.reputation = ReputationFeatures(target=result.target)
        if rep.phishtank_hit:
            result.reputation.phishtank_hit = True
            result.reputation.phishtank_detail = rep.phishtank_detail
        result.reputation.virustotal_malicious += rep.virustotal_malicious
        result.reputation.virustotal_suspicious += rep.virustotal_suspicious
        result.reputation.virustotal_harmless += rep.virustotal_harmless
        result.reputation.virustotal_undetected += rep.virustotal_undetected
        result.reputation.virustotal_total += rep.virustotal_total
        if rep.urlscan_uuid:
            result.reputation.urlscan_uuid = rep.urlscan_uuid
            result.reputation.urlscan_url = rep.urlscan_url
        for src in rep.sources:
            if src not in result.reputation.sources:
                result.reputation.sources.append(src)
        if rep.target:
            result.reputation.target = rep.target

    def _collect_errors(self) -> List[str]:
        errors: List[str] = []
        for collector in self.collectors:
            if collector.errors:
                errors.extend(collector.errors)
                collector.errors.clear()
        return errors
