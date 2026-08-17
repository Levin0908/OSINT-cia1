// Investigation page handler.
// Submits the form, polls the API, and renders the resulting report inline.

const form = document.getElementById("investigate-form");
const submitBtn = document.getElementById("submit-btn");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const target = document.getElementById("target").value.trim();
    if (!target) return;

    submitBtn.disabled = true;
    submitBtn.textContent = "Investigating…";
    showStatus("Collecting indicators from public OSINT sources…", false);
    resultsEl.classList.add("hidden");
    resultsEl.innerHTML = "";

    try {
        const response = await fetch("/api/investigate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target,
                scan: true,
                submit_urlscan: document.getElementById("submit_urlscan").checked,
            }),
        });
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `HTTP ${response.status}`);
        }
        const result = await response.json();
        renderReport(result);
        statusEl.classList.add("hidden");
    } catch (err) {
        showStatus("Investigation failed: " + err.message, true);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = "Investigate";
    }
});

function showStatus(text, isError) {
    statusEl.textContent = text;
    statusEl.classList.remove("hidden");
    statusEl.classList.toggle("error", !!isError);
}

function renderReport(r) {
    const html = [];
    html.push(reportHeader(r));
    html.push(correlations(r));
    html.push(scoreBreakdown(r));
    html.push(grid(featureCards(r)));
    html.push(iocTable(r));
    html.push(recommendations(r));
    if (r.errors && r.errors.length) html.push(errors(r));
    resultsEl.innerHTML = html.join("\n");
    resultsEl.classList.remove("hidden");
}

function reportHeader(r) {
    return `
    <div class="card report-header">
        <div class="risk-meter">
            <div class="risk-dial risk-${r.risk_level}">
                <span class="risk-number">${r.risk_score}</span>
                <span class="risk-tag">/100</span>
            </div>
            <div class="risk-meta">
                <div class="risk-level-label level-${r.risk_level}">${r.risk_level}</div>
                <div class="verdict-label">Verdict: <strong>${escape(r.verdict).replace('_', ' ')}</strong></div>
                <div class="muted mono">${escape(r.target)}</div>
                <div class="muted">Investigation ${r.id}</div>
            </div>
        </div>
        <p class="summary">${escape(r.summary)}</p>
        <div class="actions">
            <a href="/report/${r.id}" class="btn btn-primary">Open full report</a>
            <a href="/api/investigations/${r.id}/report?format=json" target="_blank" class="btn btn-tiny">JSON</a>
            <a href="/api/investigations/${r.id}/report?format=markdown" target="_blank" class="btn btn-tiny">Markdown</a>
        </div>
    </div>`;
}

function correlations(r) {
    return `
    <div class="card">
        <div class="card-header">Correlated findings</div>
        <ul class="bullet-list">
            ${(r.correlations || []).map(c => `<li>${escape(c)}</li>`).join("") || "<li class='muted'>No correlations.</li>"}
        </ul>
    </div>`;
}

function scoreBreakdown(r) {
    const rows = (r.score_breakdown || []).map(b => `
        <tr><td><span class="badge">${escape(b.component)}</span></td>
            <td>${b.points}</td><td>${escape(b.reason)}</td></tr>`).join("");
    return `
    <div class="card">
        <div class="card-header">Score breakdown</div>
        <table class="data-table">
            <thead><tr><th>Component</th><th>Points</th><th>Reason</th></tr></thead>
            <tbody>${rows || "<tr><td colspan='3' class='muted'>No contributors.</td></tr>"}</tbody>
        </table>
    </div>`;
}

function featureCards(r) {
    const cards = [];
    if (r.url) cards.push({
        title: "URL features",
        kv: [
            ["Scheme", r.url.scheme], ["Host", r.url.netloc], ["TLD", `.${r.url.tld} (risk=${r.url.tld_risk})`],
            ["Length", r.url.url_length], ["Subdomains", r.url.num_subdomains],
            ["IP host", r.url.has_ip_host], ["Punycode", r.url.punycode],
            ["Suspicious keywords", (r.url.suspicious_keywords || []).join(", ") || "—"],
            ["Brand keywords", (r.url.risk_keywords || []).join(", ") || "—"],
        ]
    });
    if (r.domain) cards.push({
        title: "Domain / WHOIS",
        kv: [
            ["Domain", r.domain.domain], ["Registrar", r.domain.registrar || "unknown"],
            ["Created", r.domain.creation_date || "unknown"], ["Age", r.domain.age_days + " days"],
            ["Expires", r.domain.expiration_date || "unknown"],
            ["NS", (r.domain.name_servers || []).join(", ") || "—"],
            ["Privacy", r.domain.is_private ? "yes" : "no"],
        ]
    });
    if (r.dns) cards.push({
        title: "DNS",
        kv: [
            ["A", (r.dns.a || []).join(", ") || "—"],
            ["AAAA", (r.dns.aaaa || []).join(", ") || "—"],
            ["MX", (r.dns.mx || []).join(", ") || "—"],
            ["NS", (r.dns.ns || []).join(", ") || "—"],
            ["SPF", r.dns.has_spf ? "yes" : "no"],
            ["DMARC", r.dns.has_dmarc ? "yes" : "no"],
            ["DKIM", r.dns.has_dkim ? "yes" : "no"],
        ]
    });
    if (r.ip) cards.push({
        title: "Hosting IP",
        kv: [
            ["IP", r.ip.ip], ["Country", r.ip.country || "—"],
            ["ISP", r.ip.isp || "—"], ["Org", r.ip.org || "—"],
            ["Reputation", r.ip.reputation],
            ["Abuse score", r.ip.abuse_confidence ?? "—"],
            ["Tor", r.ip.is_tor ? "yes" : "no"],
        ]
    });
    if (r.ssl) cards.push({
        title: "TLS certificate",
        kv: [
            ["Subject", r.ssl.subject], ["Issuer", r.ssl.issuer],
            ["Self-signed", r.ssl.self_signed ? "yes" : "no"],
            ["Expired", r.ssl.expired ? "yes" : "no"],
            ["Valid for host", r.ssl.valid_for_host ? "yes" : "no"],
            ["Days left", r.ssl.days_remaining ?? "—"],
            ["Key size", r.ssl.key_size],
        ]
    });
    if (r.content) cards.push({
        title: "Web content",
        kv: [
            ["Final URL", r.content.final_url], ["Status", r.content.status_code],
            ["Title", r.content.title || "—"],
            ["Password", r.content.has_password_field ? "yes" : "no"],
            ["Card", r.content.has_credit_card_field ? "yes" : "no"],
            ["Brand", (r.content.brand_impersonation || []).join(", ") || "—"],
            ["Redirects", (r.content.redirect_chain || []).length],
        ]
    });
    if (r.reputation) cards.push({
        title: "Threat intelligence",
        kv: [
            ["PhishTank", r.reputation.phishtank_hit ? "hit" : "no hit"],
            ["VT malicious", r.reputation.virustotal_malicious + " / " + r.reputation.virustotal_total],
            ["VT suspicious", r.reputation.virustotal_suspicious],
            ["Sources", (r.reputation.sources || []).join(", ") || "—"],
        ]
    });
    return cards.map(c => `
        <div class="card">
            <div class="card-header">${escape(c.title)}</div>
            <dl class="kv">${c.kv.map(([k, v]) => `<dt>${escape(k)}</dt><dd>${escape(String(v))}</dd>`).join("")}</dl>
        </div>`).join("");
}

function grid(inner) {
    return `<div class="card-grid">${inner}</div>`;
}

function iocTable(r) {
    const rows = (r.iocs || []).map(i => `
        <tr class="${i.malicious ? 'ioc-malicious' : ''}">
            <td><span class="badge">${escape(i.type)}</span></td>
            <td class="mono">${escape(i.value)}</td>
            <td>${escape(i.source)}</td>
            <td>${i.confidence}%</td>
            <td>${(i.tags || []).map(escape).join(", ")}</td>
        </tr>`).join("");
    return `
    <div class="card">
        <div class="card-header">Indicators of compromise</div>
        <table class="data-table">
            <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th><th>Tags</th></tr></thead>
            <tbody>${rows || "<tr><td colspan='5' class='muted'>No IOCs extracted.</td></tr>"}</tbody>
        </table>
    </div>`;
}

function recommendations(r) {
    return `
    <div class="card">
        <div class="card-header">Recommendations</div>
        <ul class="bullet-list">
            ${(r.recommendations || []).map(c => `<li>${escape(c)}</li>`).join("")}
        </ul>
    </div>`;
}

function errors(r) {
    return `
    <div class="card">
        <div class="card-header">Collector errors</div>
        <ul class="bullet-list">
            ${(r.errors || []).map(e => `<li class="muted">${escape(e)}</li>`).join("")}
        </ul>
    </div>`;
}

function escape(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
