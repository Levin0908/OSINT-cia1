"""Risk scoring engine.

The score is a weighted combination of evidence from every collector
that successfully returned data. Each finding contributes a number of
points and a human-readable reason. The total is capped at 100.

Weights are intentionally conservative so a single weak signal cannot
move the verdict to "phishing" by itself; multiple must agree.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List

import config
from core.models import (
    ContentFeatures,
    DnsFeatures,
    DomainFeatures,
    InvestigationResult,
    IpFeatures,
    ReputationFeatures,
    ScoreBreakdown,
    SslFeatures,
    UrlFeatures,
)


def _add(breakdown: List[ScoreBreakdown], component: str, points: int, reason: str) -> None:
    if points <= 0:
        return
    breakdown.append(ScoreBreakdown(component=component, points=points, reason=reason))


# ---------------------------------------------------------------------------
# Per-source score helpers
# ---------------------------------------------------------------------------
def score_url(url: UrlFeatures) -> List[ScoreBreakdown]:
    if not url:
        return []
    breakdown: List[ScoreBreakdown] = []
    if url.url_length > 100:
        _add(breakdown, "url.length", min(8, (url.url_length - 100) // 25),
             f"URL length {url.url_length} characters")
    if url.has_ip_host:
        _add(breakdown, "url.ip_host", 15, "URL uses a raw IPv4 host instead of a domain")
    if url.punycode:
        _add(breakdown, "url.punycode", 10, "Hostname uses punycode (homograph risk)")
    if url.tld_risk:
        _add(breakdown, "url.tld", url.tld_risk, f"Risky TLD .{url.tld}")
    if url.suspicious_keywords:
        _add(breakdown, "url.keywords",
             min(20, 5 * len(url.suspicious_keywords)),
             f"Suspicious keyword(s) in URL: {', '.join(url.suspicious_keywords[:5])}")
    if url.risk_keywords:
        _add(breakdown, "url.brand",
             min(20, 10 * len(url.risk_keywords)),
             f"Brand impersonation keyword(s): {', '.join(url.risk_keywords[:3])}")
    if url.num_subdomains >= 3:
        _add(breakdown, "url.subdomains", 8,
             f"Excessive subdomain depth ({url.num_subdomains})")
    return breakdown


def score_domain(domain: DomainFeatures) -> List[ScoreBreakdown]:
    if not domain:
        return []
    breakdown: List[ScoreBreakdown] = []
    if domain.age_days is None:
        _add(breakdown, "domain.age", 6, "Domain age could not be determined")
    elif domain.age_days < 30:
        _add(breakdown, "domain.age", 10, f"Domain registered only {domain.age_days} days ago")
    elif domain.age_days < 180:
        _add(breakdown, "domain.age", 6, f"Domain is only {domain.age_days} days old")
    if domain.expiration_date and (domain.expiration_date - datetime.now(timezone.utc)).days < 90:
        _add(breakdown, "domain.expires", 5, "Domain expires within 90 days")
    if domain.is_private:
        _add(breakdown, "domain.privacy", 4, "WHOIS uses privacy/redacted registrant")
    if not domain.name_servers:
        _add(breakdown, "domain.ns", 5, "No name servers discovered")
    return breakdown


def score_ip(ip: IpFeatures) -> List[ScoreBreakdown]:
    if not ip:
        return []
    breakdown: List[ScoreBreakdown] = []
    if ip.reputation == "malicious":
        _add(breakdown, "ip.reputation", 20,
             f"IP marked malicious (AbuseIPDB confidence={ip.abuse_confidence})")
    elif ip.reputation == "suspicious":
        _add(breakdown, "ip.reputation", 12,
             f"IP marked suspicious (AbuseIPDB confidence={ip.abuse_confidence})")
    if ip.is_tor:
        _add(breakdown, "ip.tor", 8, "IP is a known Tor exit node")
    if ip.is_proxy:
        _add(breakdown, "ip.proxy", 5, "IP is a known proxy / VPN")
    return breakdown


def score_ssl(ssl: SslFeatures) -> List[ScoreBreakdown]:
    if not ssl:
        return []
    breakdown: List[ScoreBreakdown] = []
    if ssl.self_signed:
        _add(breakdown, "ssl.self_signed", 8, "TLS certificate is self-signed")
    if ssl.expired:
        _add(breakdown, "ssl.expired", 12, "TLS certificate has expired")
    if not ssl.valid_for_host:
        _add(breakdown, "ssl.mismatch", 15,
             "TLS certificate does not match the hostname")
    if ssl.key_size and ssl.key_size < 2048 and "ECC" not in (ssl.signature_algorithm or "").upper() and "EC" not in (ssl.signature_algorithm or "").upper():
        _add(breakdown, "ssl.key", 4, f"Weak TLS key size ({ssl.key_size} bits)")
    if ssl.days_remaining is not None and 0 < ssl.days_remaining < 7:
        _add(breakdown, "ssl.expiry", 4,
             f"Certificate expires in {ssl.days_remaining} days")
    return breakdown


def score_dns(dns: DnsFeatures) -> List[ScoreBreakdown]:
    if not dns:
        return []
    breakdown: List[ScoreBreakdown] = []
    if not dns.mx:
        _add(breakdown, "dns.no_mx", 6, "Domain has no MX records (cannot receive email)")
    if not dns.has_spf:
        _add(breakdown, "dns.no_spf", 4, "No SPF record published")
    if not dns.has_dmarc:
        _add(breakdown, "dns.no_dmarc", 10, "No DMARC record published")
    if not dns.has_dkim:
        _add(breakdown, "dns.no_dkim", 4, "No DKIM record discovered")
    if dns.cname:
        _add(breakdown, "dns.cname", 2, "Domain is a CNAME alias")
    return breakdown


def score_content(content: ContentFeatures) -> List[ScoreBreakdown]:
    if not content:
        return []
    breakdown: List[ScoreBreakdown] = []
    if content.has_password_field:
        _add(breakdown, "content.password_field", 12,
             "Page contains a password input")
    if content.has_credit_card_field:
        _add(breakdown, "content.card_field", 15,
             "Page contains a credit card input")
    if content.brand_impersonation:
        _add(breakdown, "content.brand",
             min(20, 10 * len(content.brand_impersonation)),
             f"Brand impersonation detected: {', '.join(content.brand_impersonation[:3])}")
    if len(content.redirect_chain) > 3:
        _add(breakdown, "content.redirects", 8,
             f"Long redirect chain ({len(content.redirect_chain)} hops)")
    if content.external_resources:
        _add(breakdown, "content.external", 7,
             f"Page loads resources from {len(content.external_resources)} external hosts")
    if content.status_code and content.status_code >= 400:
        _add(breakdown, "content.error", 4,
             f"Server returned HTTP {content.status_code}")
    return breakdown


def score_reputation(rep: ReputationFeatures) -> List[ScoreBreakdown]:
    if not rep:
        return []
    breakdown: List[ScoreBreakdown] = []
    if rep.phishtank_hit:
        _add(breakdown, "rep.phishtank", 30, "Listed in the PhishTank verified database")
    if rep.virustotal_malicious:
        _add(breakdown, "rep.virustotal",
             min(40, 7 * rep.virustotal_malicious),
             f"VirusTotal engines flagged as malicious: {rep.virustotal_malicious}/{rep.virustotal_total}")
    if rep.virustotal_suspicious:
        _add(breakdown, "rep.virustotal_suspicious",
             min(20, 3 * rep.virustotal_suspicious),
             f"VirusTotal engines flagged as suspicious: {rep.virustotal_suspicious}")
    return breakdown


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------
def compute_score(result: InvestigationResult) -> None:
    """Populate ``result.score_breakdown``, ``risk_score``, ``risk_level``,
    ``verdict`` and ``recommendations`` from the collected evidence."""
    breakdown: List[ScoreBreakdown] = []
    breakdown += score_url(result.url)
    breakdown += score_domain(result.domain)
    breakdown += score_ip(result.ip)
    breakdown += score_ssl(result.ssl)
    breakdown += score_dns(result.dns)
    breakdown += score_content(result.content)
    breakdown += score_reputation(result.reputation)

    total = sum(b.points for b in breakdown)
    result.score_breakdown = sorted(breakdown, key=lambda b: -b.points)
    result.risk_score = min(100, total)

    if result.risk_score >= 75:
        result.risk_level = "critical"
        result.verdict = "phishing"
    elif result.risk_score >= 55:
        result.risk_level = "high"
        result.verdict = "likely_phishing"
    elif result.risk_score >= 30:
        result.risk_level = "medium"
        result.verdict = "suspicious"
    elif result.risk_score >= 10:
        result.risk_level = "low"
        result.verdict = "benign"
    else:
        result.risk_level = "informational"
        result.verdict = "unknown"

    result.recommendations = _recommendations(result)
    result.summary = _summary(result)


def _recommendations(result: InvestigationResult) -> list[str]:
    recs: list[str] = []
    if result.verdict in {"phishing", "likely_phishing"}:
        recs.append("Block the URL/domain at the network perimeter and add it to the threat-intel feed.")
        recs.append("Notify users who may have interacted with the page; force a password reset if credentials were entered.")
    if result.ssl and result.ssl.expired:
        recs.append("Investigate why the TLS certificate has lapsed.")
    if result.domain and result.domain.age_days is not None and result.domain.age_days < 30:
        recs.append("Domain is newly registered — typical pattern of throw-away phishing infrastructure.")
    if result.reputation and result.reputation.phishtank_hit:
        recs.append("Cross-reference with the PhishTank database and submit internal incidents to the community database.")
    if result.content and result.content.has_password_field:
        recs.append("Page contains a credential capture form — treat as active credential harvesting.")
    if not result.dns or not (result.dns.has_spf and result.dns.has_dmarc):
        recs.append("Configure SPF, DKIM and DMARC to prevent spoofing of the legitimate domain.")
    if result.ip and result.ip.reputation in {"malicious", "suspicious"}:
        recs.append("Hosting IP has abuse history — escalate to the abuse contact.")
    if not recs:
        recs.append("No high-risk indicators detected. Continue passive monitoring.")
    return recs


def _summary(result: InvestigationResult) -> str:
    parts = [f"Target {result.target} scored {result.risk_score}/100 ({result.risk_level})."]
    if result.domain and result.domain.age_days is not None:
        parts.append(f"Domain is {result.domain.age_days} days old.")
    if result.reputation and result.reputation.phishtank_hit:
        parts.append("Positive hit in PhishTank.")
    if result.reputation and result.reputation.virustotal_malicious:
        parts.append(f"{result.reputation.virustotal_malicious} VirusTotal engines flagged the target.")
    if result.content and result.content.brand_impersonation:
        parts.append(f"Brand impersonation: {', '.join(result.content.brand_impersonation)}.")
    if result.content and result.content.has_password_field:
        parts.append("Page contains a password input.")
    return " ".join(parts)
