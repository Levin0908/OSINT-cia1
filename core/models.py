"""Pydantic data models used across collectors, the correlator,
and the API layer. Every IOC is represented as a structured object
so the correlation engine can compare evidence from different sources.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# IOC primitives
# ---------------------------------------------------------------------------
class IOC(BaseModel):
    """A single indicator of compromise extracted from one OSINT source."""
    type: str                 # url | domain | ip | ssl | dns | whois | content | reputation
    value: str                # The indicator itself
    source: str               # which collector / external API produced it
    malicious: bool = False
    confidence: int = 0       # 0-100
    tags: List[str] = Field(default_factory=list)
    raw: Optional[Dict[str, Any]] = None
    collected_at: datetime = Field(default_factory=datetime.utcnow)


class InvestigationRequest(BaseModel):
    target: str
    scan: bool = True
    include_urlscan: bool = False        # requires URLSCAN_API_KEY
    submit_urlscan: bool = False


# ---------------------------------------------------------------------------
# Per-source findings returned by collectors
# ---------------------------------------------------------------------------
class UrlFeatures(BaseModel):
    full_url: str
    scheme: str
    netloc: str
    path: str
    query: str
    suspicious_keywords: List[str] = Field(default_factory=list)
    has_ip_host: bool = False
    punycode: bool = False
    url_length: int = 0
    num_subdomains: int = 0
    tld: str = ""
    tld_risk: int = 0
    risk_keywords: List[str] = Field(default_factory=list)


class DomainFeatures(BaseModel):
    domain: str
    tld: str
    sld: str
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    registrar: Optional[str] = None
    registrant: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: List[str] = Field(default_factory=list)
    statuses: List[str] = Field(default_factory=list)
    age_days: Optional[int] = None
    is_private: bool = False
    dnssec: Optional[bool] = None


class IpFeatures(BaseModel):
    ip: str
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    reverse_dns: Optional[str] = None
    abuse_confidence: Optional[int] = None
    total_reports: Optional[int] = None
    is_tor: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    reputation: str = "unknown"   # malicious | suspicious | neutral | clean


class SslFeatures(BaseModel):
    subject: str = ""
    issuer: str = ""
    common_name: str = ""
    alt_names: List[str] = Field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    self_signed: bool = False
    expired: bool = False
    valid_for_host: bool = False
    serial_number: str = ""
    signature_algorithm: str = ""
    key_size: int = 0
    is_ecdsa: bool = False
    ct_log_hits: Optional[int] = None


class DnsFeatures(BaseModel):
    domain: str
    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    mx: List[str] = Field(default_factory=list)
    ns: List[str] = Field(default_factory=list)
    txt: List[str] = Field(default_factory=list)
    cname: List[str] = Field(default_factory=list)
    soa: Optional[str] = None
    has_spf: bool = False
    has_dmarc: bool = False
    has_dkim: bool = False
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None


class ContentFeatures(BaseModel):
    url: str
    final_url: str
    status_code: int = 0
    title: str = ""
    meta_description: str = ""
    server: str = ""
    powered_by: str = ""
    has_password_field: bool = False
    has_credit_card_field: bool = False
    external_resources: List[str] = Field(default_factory=list)
    brand_impersonation: List[str] = Field(default_factory=list)
    redirect_chain: List[str] = Field(default_factory=list)
    response_size: int = 0
    content_type: str = ""
    cookies: List[str] = Field(default_factory=list)


class ReputationFeatures(BaseModel):
    target: str
    phishtank_hit: bool = False
    phishtank_detail: Optional[Dict[str, Any]] = None
    virustotal_malicious: int = 0
    virustotal_suspicious: int = 0
    virustotal_harmless: int = 0
    virustotal_undetected: int = 0
    virustotal_total: int = 0
    urlscan_uuid: Optional[str] = None
    urlscan_url: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Aggregated investigation result
# ---------------------------------------------------------------------------
class ScoreBreakdown(BaseModel):
    component: str
    points: int
    reason: str


class InvestigationResult(BaseModel):
    id: Optional[int] = None
    target: str
    is_url: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    risk_score: int = 0
    risk_level: str = "unknown"        # low | medium | high | critical
    verdict: str = "unknown"           # benign | suspicious | likely_phishing | phishing
    summary: str = ""
    iocs: List[IOC] = Field(default_factory=list)
    url: Optional[UrlFeatures] = None
    domain: Optional[DomainFeatures] = None
    ip: Optional[IpFeatures] = None
    ssl: Optional[SslFeatures] = None
    dns: Optional[DnsFeatures] = None
    content: Optional[ContentFeatures] = None
    reputation: Optional[ReputationFeatures] = None
    score_breakdown: List[ScoreBreakdown] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    correlations: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    def target_id(self) -> str:
        """Filesystem-safe identifier for artefacts."""
        from datetime import datetime
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in self.target)
        safe = safe.strip("._") or "target"
        ts = self.timestamp.strftime("%Y%m%dT%H%M%S") if self.timestamp else datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        return f"{ts}_{self.id or 0}_{safe[:60]}"
