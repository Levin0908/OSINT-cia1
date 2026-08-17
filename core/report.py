"""Report generator — JSON, Markdown, and PDF rendering."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import config
from core.models import InvestigationResult


class ReportGenerator:
    """Stateless helper that produces human-readable artefacts."""

    def __init__(self, output_dir: str | None = None) -> None:
        self.output_dir = Path(output_dir or config.REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------
    def to_json(self, result: InvestigationResult, indent: int = 2) -> str:
        return json.dumps(result.model_dump(mode="json"), indent=indent, default=str)

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------
    def to_markdown(self, result: InvestigationResult) -> str:
        lines: list[str] = []
        lines.append(f"# OSINT Phishing Investigation Report")
        lines.append("")
        lines.append(f"- **Target:** `{result.target}`")
        lines.append(f"- **Generated:** {datetime.utcnow().isoformat()}Z")
        lines.append(f"- **Risk score:** {result.risk_score}/100")
        lines.append(f"- **Risk level:** {result.risk_level}")
        lines.append(f"- **Verdict:** {result.verdict}")
        lines.append("")
        lines.append("## Summary")
        lines.append(result.summary)
        lines.append("")
        lines.append("## Correlated findings")
        for note in result.correlations:
            lines.append(f"- {note}")
        lines.append("")
        lines.append("## Score breakdown")
        lines.append("| Component | Points | Reason |")
        lines.append("| --- | ---: | --- |")
        for entry in result.score_breakdown:
            lines.append(f"| {entry.component} | {entry.points} | {entry.reason} |")
        lines.append("")
        if result.url:
            lines.append("## URL features")
            lines.append(f"- Scheme: `{result.url.scheme}`")
            lines.append(f"- Host: `{result.url.netloc}`")
            lines.append(f"- TLD: `{result.url.tld}` (risk={result.url.tld_risk})")
            lines.append(f"- Suspicious keywords: {', '.join(result.url.suspicious_keywords) or 'none'}")
            lines.append(f"- Brand impersonation: {', '.join(result.url.risk_keywords) or 'none'}")
            lines.append("")
        if result.domain:
            lines.append("## Domain / WHOIS")
            lines.append(f"- Domain: `{result.domain.domain}`")
            lines.append(f"- Registrar: {result.domain.registrar or 'unknown'}")
            lines.append(f"- Creation date: {result.domain.creation_date}")
            lines.append(f"- Age: {result.domain.age_days} days")
            lines.append(f"- NS: {', '.join(result.domain.name_servers) or 'n/a'}")
            lines.append("")
        if result.dns:
            lines.append("## DNS")
            lines.append(f"- A: {', '.join(result.dns.a) or 'n/a'}")
            lines.append(f"- AAAA: {', '.join(result.dns.aaaa) or 'n/a'}")
            lines.append(f"- MX: {', '.join(result.dns.mx) or 'n/a'}")
            lines.append(f"- SPF: {'yes' if result.dns.has_spf else 'no'}")
            lines.append(f"- DMARC: {'yes' if result.dns.has_dmarc else 'no'}")
            lines.append(f"- DKIM: {'yes' if result.dns.has_dkim else 'no'}")
            lines.append("")
        if result.ip:
            lines.append("## Hosting IP")
            lines.append(f"- IP: `{result.ip.ip}`")
            lines.append(f"- Country: {result.ip.country}")
            lines.append(f"- ISP/Org: {result.ip.isp} / {result.ip.org}")
            lines.append(f"- Reputation: {result.ip.reputation}")
            lines.append(f"- Abuse confidence: {result.ip.abuse_confidence}")
            lines.append("")
        if result.ssl:
            lines.append("## TLS certificate")
            lines.append(f"- Subject: {result.ssl.subject}")
            lines.append(f"- Issuer: {result.ssl.issuer}")
            lines.append(f"- Self-signed: {result.ssl.self_signed}")
            lines.append(f"- Expired: {result.ssl.expired}")
            lines.append(f"- Valid for host: {result.ssl.valid_for_host}")
            lines.append(f"- Days remaining: {result.ssl.days_remaining}")
            lines.append("")
        if result.content:
            lines.append("## Web content")
            lines.append(f"- Final URL: {result.content.final_url}")
            lines.append(f"- Status: {result.content.status_code}")
            lines.append(f"- Title: {result.content.title}")
            lines.append(f"- Has password field: {result.content.has_password_field}")
            lines.append(f"- Has credit card field: {result.content.has_credit_card_field}")
            lines.append(f"- Brand impersonation: {', '.join(result.content.brand_impersonation) or 'none'}")
            lines.append(f"- Redirect chain: {' -> '.join(result.content.redirect_chain)}")
            lines.append("")
        if result.reputation:
            lines.append("## Threat intelligence")
            lines.append(f"- PhishTank hit: {result.reputation.phishtank_hit}")
            lines.append(f"- VirusTotal malicious: {result.reputation.virustotal_malicious}/{result.reputation.virustotal_total}")
            lines.append(f"- VirusTotal suspicious: {result.reputation.virustotal_suspicious}")
            lines.append(f"- Sources: {', '.join(result.reputation.sources) or 'none'}")
            lines.append("")
        if result.iocs:
            lines.append("## Indicators of compromise")
            for ioc in result.iocs:
                lines.append(f"- [{ioc.type}] `{ioc.value}` (malicious={ioc.malicious}, confidence={ioc.confidence})")
            lines.append("")
        if result.recommendations:
            lines.append("## Recommendations")
            for rec in result.recommendations:
                lines.append(f"- {rec}")
            lines.append("")
        if result.errors:
            lines.append("## Collector errors")
            for err in result.errors:
                lines.append(f"- {err}")
            lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # PDF
    # ------------------------------------------------------------------
    def to_pdf(self, result: InvestigationResult) -> Path:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import cm
            from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                            Table, TableStyle)
            from reportlab.lib import colors
        except ImportError:
            path = self.output_dir / f"{result.target_id()}.json"
            path.write_text(self.to_json(result))
            return path

        path = self.output_dir / f"{result.target_id()}.pdf"
        doc = SimpleDocTemplate(str(path), pagesize=A4,
                                leftMargin=2 * cm, rightMargin=2 * cm,
                                topMargin=2 * cm, bottomMargin=2 * cm)
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph("OSINT Phishing Investigation Report", styles["Title"]))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(f"<b>Target:</b> {result.target}", styles["Normal"]))
        story.append(Paragraph(f"<b>Generated:</b> {datetime.utcnow().isoformat()}Z", styles["Normal"]))
        story.append(Paragraph(f"<b>Risk score:</b> {result.risk_score}/100 ({result.risk_level})", styles["Normal"]))
        story.append(Paragraph(f"<b>Verdict:</b> {result.verdict}", styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("Summary", styles["Heading2"]))
        story.append(Paragraph(result.summary, styles["BodyText"]))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("Score breakdown", styles["Heading2"]))
        rows = [["Component", "Points", "Reason"]]
        for entry in result.score_breakdown:
            rows.append([entry.component, str(entry.points), entry.reason])
        if len(rows) == 1:
            rows.append(["-", "-", "No findings"])
        table = Table(rows, hAlign="LEFT", colWidths=[4 * cm, 2 * cm, 11 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.gray),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("Recommendations", styles["Heading2"]))
        for rec in result.recommendations:
            story.append(Paragraph(f"• {rec}", styles["BodyText"]))
        doc.build(story)
        return path

    # ------------------------------------------------------------------
    # convenience
    # ------------------------------------------------------------------
    def save(self, result: InvestigationResult, fmt: str = "json") -> Path:
        if fmt == "markdown":
            path = self.output_dir / f"{result.target_id()}.md"
            path.write_text(self.to_markdown(result), encoding="utf-8")
            return path
        if fmt == "pdf":
            return self.to_pdf(result)
        path = self.output_dir / f"{result.target_id()}.json"
        path.write_text(self.to_json(result), encoding="utf-8")
        return path
