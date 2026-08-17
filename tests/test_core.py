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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
