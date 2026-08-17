"""IOC correlation engine.

The correlator does not need any external service. It merges the
findings from every collector and surfaces patterns that become
visible only when evidence is combined, e.g.:

* Newly registered domain hosted on a malicious IP
* Brand keyword in URL served by a self-signed certificate
* PhishTank hit + no email authentication
"""
from __future__ import annotations

from typing import List

from core.models import InvestigationResult


def correlate(result: InvestigationResult) -> List[str]:
    notes: List[str] = []

    domain = result.domain
    ip = result.ip
    dns = result.dns
    ssl = result.ssl
    url = result.url
    content = result.content
    rep = result.reputation

    if domain and domain.age_days is not None and domain.age_days < 30 and ip and ip.reputation in {"malicious", "suspicious"}:
        notes.append(
            f"Newly registered domain ({domain.age_days} days) hosted on IP with "
            f"reputation={ip.reputation} — classic throw-away phishing pattern."
        )
    if url and url.risk_keywords and ssl and not ssl.valid_for_host:
        notes.append(
            "Brand keyword appears in URL but TLS certificate does not match the host — "
            "credential-harvesting campaign likely."
        )
    if rep and rep.phishtank_hit and dns and not dns.has_dmarc:
        notes.append("PhishTank hit combined with missing DMARC — the legitimate organisation is unprotected.")
    if rep and rep.virustotal_malicious and content and content.has_password_field:
        notes.append("Multi-engine detection + on-page credential form — high-confidence phishing page.")
    if content and content.brand_impersonation and content.has_password_field:
        notes.append(
            f"Brand impersonation ({', '.join(content.brand_impersonation)}) "
            "with a credential capture form."
        )
    if url and url.has_ip_host and not url.full_url.startswith("https://"):
        notes.append("IP-host URL served over plaintext HTTP.")
    if dns and dns.mx and not any(dns.mx):
        notes.append("MX records present but TXT records absent — incomplete email configuration.")
    if ssl and ssl.self_signed and url and url.scheme == "https":
        notes.append("HTTPS page served with a self-signed certificate.")
    if ip and ip.is_tor and content and content.has_password_field:
        notes.append("Tor exit used to host a credential capture form.")
    if content and content.redirect_chain and len(content.redirect_chain) > 4:
        notes.append(
            f"Page redirected through {len(content.redirect_chain)} hops — common evasion technique."
        )
    if domain and domain.registrar and "privacy" in (domain.registrar or "").lower() and domain.age_days is not None and domain.age_days < 180:
        notes.append("Privacy-protected registration combined with a young domain.")

    if not notes:
        notes.append("No correlated high-risk patterns detected.")
    return notes
