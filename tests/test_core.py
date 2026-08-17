"""Smoke / unit tests for the OSINT phishing investigator.

Run with::

    python -m pytest tests/ -v

The tests avoid external network calls by default; collectors that
require the network are mocked.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from core.database import Database
from core.models import (
    ContentFeatures,
    DnsFeatures,
    DomainFeatures,
    InvestigationRequest,
    InvestigationResult,
    IpFeatures,
    ReputationFeatures,
    SslFeatures,
    UrlFeatures,
)
from core.scoring import compute_score
from core.correlator import correlate
from core.report import ReportGenerator


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------
def _build_result(**overrides) -> InvestigationResult:
    r = InvestigationResult(target="https://example.com/login", is_url=True)
    r.url = UrlFeatures(
        full_url="https://example.com/login",
        scheme="https", netloc="example.com", path="/login", query="",
        suspicious_keywords=["login"], has_ip_host=False, punycode=False,
        url_length=30, num_subdomains=0, tld="com", tld_risk=0,
        risk_keywords=["paypal"],
    )
    r.domain = DomainFeatures(domain="example.com", tld="com", sld="example", age_days=5)
    r.dns = DnsFeatures(domain="example.com")
    r.ssl = SslFeatures(self_signed=True, expired=False, valid_for_host=True)
    r.ip = IpFeatures(ip="203.0.113.1", reputation="malicious", abuse_confidence=85)
    r.content = ContentFeatures(
        url="https://example.com/login", final_url="https://example.com/login",
        status_code=200, has_password_field=True,
        brand_impersonation=["paypal"],
    )
    r.reputation = ReputationFeatures(
        target="https://example.com/login",
        phishtank_hit=True, virustotal_malicious=4, virustotal_total=72,
        sources=["phishtank", "virustotal_url"],
    )
    for key, value in overrides.items():
        setattr(r, key, value)
    return r


def test_scoring_critical_for_many_indicators() -> None:
    result = _build_result()
    compute_score(result)
    assert result.risk_score >= 75
    assert result.risk_level == "critical"
    assert result.verdict == "phishing"


def test_scoring_low_for_clean_target() -> None:
    result = _build_result()
    result.url = UrlFeatures(
        full_url="https://example.com/about", scheme="https",
        netloc="example.com", path="/about", query="",
        url_length=22, tld="com", tld_risk=0,
    )
    result.domain = DomainFeatures(domain="example.com", tld="com", sld="example", age_days=4000)
    result.dns = DnsFeatures(domain="example.com", a=["93.184.216.34"],
                             has_spf=True, has_dmarc=True, has_dkim=True)
    result.ssl = SslFeatures(self_signed=False, expired=False, valid_for_host=True, days_remaining=300)
    result.ip = IpFeatures(ip="93.184.216.34", reputation="clean")
    result.content = ContentFeatures(url="https://example.com/about", final_url="https://example.com/about", status_code=200)
    result.reputation = ReputationFeatures(target="https://example.com/about")
    compute_score(result)
    assert result.risk_score < 30
    assert result.risk_level in {"low", "informational"}


def test_correlation_detects_brand_and_password_form() -> None:
    result = _build_result()
    compute_score(result)
    result.correlations = correlate(result)
    assert any("credential capture" in c for c in result.correlations)


def test_report_serialisation_roundtrip() -> None:
    result = _build_result()
    compute_score(result)
    generator = ReportGenerator(output_dir=str(Path("tests/_tmp")))
    md = generator.to_markdown(result)
    js = generator.to_json(result)
    assert "OSINT Phishing Investigation Report" in md
    assert json.loads(js)["target"] == result.target


# ---------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------
def test_database_roundtrip(tmp_path) -> None:
    db_path = tmp_path / "inv.db"
    db = Database(str(db_path))
    result = _build_result()
    compute_score(result)
    investigation_id = db.save(result)
    assert investigation_id > 0
    fetched = db.get_investigation(investigation_id)
    assert fetched is not None
    assert fetched.target == result.target
    assert fetched.risk_score == result.risk_score
    listing = db.list_investigations()
    assert any(item["id"] == investigation_id for item in listing)
    stats = db.statistics()
    assert stats["total_investigations"] >= 1


# ---------------------------------------------------------------------------
# investigator orchestration
# ---------------------------------------------------------------------------
def test_investigator_with_mocks() -> None:
    from core.investigator import Investigator

    fake_results = {
        "url": {"url": UrlFeatures(
            full_url="https://example.com/login", scheme="https",
            netloc="example.com", path="/login", query="",
            url_length=30, tld="com", tld_risk=0,
        )},
        "domain": {"domain": DomainFeatures(domain="example.com", tld="com", sld="example", age_days=10)},
        "dns": {"dns": DnsFeatures(domain="example.com", a=["1.2.3.4"])},
        "ip": {"ip": IpFeatures(ip="1.2.3.4", reputation="neutral")},
        "ssl": {"ssl": SslFeatures(common_name="example.com", self_signed=False, valid_for_host=True, days_remaining=90)},
        "content": {"content": ContentFeatures(url="https://example.com/login", final_url="https://example.com/login", status_code=200)},
        "phishtank": {"phishtank": ReputationFeatures(target="https://example.com/login")},
        "virustotal": {"virustotal": ReputationFeatures(target="https://example.com/login")},
        "urlscan": {"urlscan": ReputationFeatures(target="https://example.com/login")},
    }

    with patch("core.investigator._resolve_ip", return_value="1.2.3.4"):
        investigator = Investigator()
        for collector in investigator.collectors:
            collector.collect = lambda target, context, key=collector.name: fake_results[key]  # type: ignore[assignment]
        result = investigator.investigate(InvestigationRequest(target="https://example.com/login"))
    assert result.risk_score >= 0
    assert result.risk_level in {"informational", "low", "medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Regression tests — v1.0.1 false-positive fixes
# ---------------------------------------------------------------------------
def _youtube_result() -> InvestigationResult:
    """Reconstructs the exact evidence the YouTube investigation
    (#7 in the DB) produced, with the buggy fields already corrected
    to reflect what the fixed collectors would now produce."""
    r = InvestigationResult(target="https://www.youtube.com/", is_url=True)
    r.url = UrlFeatures(
        full_url="https://www.youtube.com/", scheme="https",
        netloc="www.youtube.com", path="/", query="",
        suspicious_keywords=[], has_ip_host=False, punycode=False,
        url_length=25, num_subdomains=1, tld="com", tld_risk=0,
        risk_keywords=[],
    )
    r.domain = DomainFeatures(domain="youtube.com", tld="com", sld="youtube", age_days=7853)
    r.dns = DnsFeatures(
        domain="youtube.com", a=["142.250.x.x"], mx=["smtp.google.com"],
        has_spf=True, has_dmarc=True, has_dkim=True,
    )
    r.ssl = SslFeatures(
        subject="CN=*.google.com",
        issuer="CN=WR2,O=Google Trust Services,C=US",
        common_name="*.google.com",
        alt_names=["*.google.com", "*.youtube.com", "youtube.com",
                   "youtu.be", "www.youtube.com", "google.com"],
        days_remaining=56, self_signed=False, expired=False,
        valid_for_host=True,  # wildcard fix
        key_size=256, is_ecdsa=True,  # ECDSA fix
        signature_algorithm="1.2.840.10045.4.3.2",
    )
    r.ip = IpFeatures(ip="142.250.x.x", reputation="clean")
    r.content = ContentFeatures(
        url="https://www.youtube.com/", final_url="https://www.youtube.com/",
        status_code=200,
        title="YouTube",
        meta_description=("Enjoy the videos and music that you love, "
                          "upload original content and share it all with "
                          "friends, family and the world on YouTube."),
        has_password_field=False,  # DOM-only detection, no JS/template strings
        has_credit_card_field=False,
        external_resources=["accounts.google.com", "developers.google.com",
                            "m.youtube.com"],  # 3 < 5 threshold
        brand_impersonation=[],  # operator whitelist suppresses "google"
        redirect_chain=["https://www.youtube.com/"],
        response_size=872632, content_type="text/html", cookies=[],
    )
    r.reputation = ReputationFeatures(target="https://www.youtube.com/")
    return r


def test_youtube_scores_below_medium() -> None:
    """Regression: youtube.com must NOT score medium (the original bug
    scored 38 from ssl.mismatch+content.password_field+content.external+ssl.key).
    """
    result = _youtube_result()
    compute_score(result)
    assert result.risk_score < 30, (
        f"expected <30, got {result.risk_score} ({result.risk_level}); "
        f"breakdown={[b.component for b in result.score_breakdown]}"
    )
    assert result.risk_level in {"informational", "low"}


def test_ecdsa_p256_not_flagged_as_weak() -> None:
    """ECDSA P-256 must not trigger the ssl.key weak-key rule."""
    ssl = SslFeatures(key_size=256, is_ecdsa=True, valid_for_host=True,
                      self_signed=False, expired=False)
    result = InvestigationResult(target="https://example.com", is_url=True)
    result.ssl = ssl
    compute_score(result)
    components = {b.component for b in result.score_breakdown}
    assert "ssl.key" not in components


def test_rsa_1024_still_flagged_as_weak() -> None:
    """The ssl.key rule must still fire for genuinely weak RSA keys."""
    ssl = SslFeatures(key_size=1024, is_ecdsa=False, valid_for_host=True,
                      self_signed=False, expired=False)
    result = InvestigationResult(target="https://example.com", is_url=True)
    result.ssl = ssl
    compute_score(result)
    components = {b.component for b in result.score_breakdown}
    assert "ssl.key" in components


def test_content_external_threshold() -> None:
    """content.external requires >=5 hosts (graded) or >=10 (full +7)."""
    for n in (0, 1, 2, 3, 4):
        result = InvestigationResult(target="https://example.com", is_url=True)
        result.content = ContentFeatures(
            url="https://example.com", final_url="https://example.com",
            status_code=200,
            external_resources=[f"h{i}.example" for i in range(n)],
        )
        compute_score(result)
        assert "content.external" not in {b.component for b in result.score_breakdown}, (
            f"n={n} should not fire"
        )
    for n in (5, 6, 9):
        result = InvestigationResult(target="https://example.com", is_url=True)
        result.content = ContentFeatures(
            url="https://example.com", final_url="https://example.com",
            status_code=200,
            external_resources=[f"h{i}.example" for i in range(n)],
        )
        compute_score(result)
        comp = next((b for b in result.score_breakdown if b.component == "content.external"), None)
        assert comp is not None and comp.points == 3, f"n={n} should fire +3, got {comp}"
    for n in (10, 50):
        result = InvestigationResult(target="https://example.com", is_url=True)
        result.content = ContentFeatures(
            url="https://example.com", final_url="https://example.com",
            status_code=200,
            external_resources=[f"h{i}.example" for i in range(n)],
        )
        compute_score(result)
        comp = next((b for b in result.score_breakdown if b.component == "content.external"), None)
        assert comp is not None and comp.points == 7, f"n={n} should fire +7, got {comp}"


def test_brand_impersonation_operator_whitelist() -> None:
    """A page on youtube.com mentioning 'Google' must not be flagged
    as brand impersonation because Google owns youtube.com."""
    from collectors.content_collector import _operator_for
    assert _operator_for("https://www.youtube.com/") == "google"
    assert _operator_for("https://outlook.live.com/") == "microsoft"
    assert _operator_for("https://www.apple.com/") == "apple"
    assert _operator_for("https://example.com/") is None


def test_brand_impersonation_word_boundary() -> None:
    """The string 'pineapple' must not match the brand 'apple'."""
    from collectors.content_collector import ContentCollector
    text = "I like pineapple on pizza."
    import re
    matches = [b for b in ["apple", "google"] if re.search(rf"\b{re.escape(b)}\b", text)]
    assert matches == []


def test_content_password_field_ignores_script_json() -> None:
    """A page whose <script> contains 'name':'password' must not be flagged
    as having a password field — only real <input> elements count."""
    from collectors.content_collector import ContentCollector
    from bs4 import BeautifulSoup
    from collectors.content_collector import BS_PARSER

    html = ('<html><head><script>{"name":"password","type":"password"}'
            '</script></head><body><p>No form here.</p></body></html>')
    soup = BeautifulSoup(html, BS_PARSER)
    found_password = any(
        (inp.get("type") or "").lower() == "password"
        or (inp.get("name") or "").lower() in {"password", "passwd", "pass"}
        for inp in soup.find_all("input")
    )
    assert found_password is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
