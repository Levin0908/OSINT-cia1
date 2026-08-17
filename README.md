# OSINT Phishing Investigation Platform

Automated phishing investigation platform that aggregates publicly
available threat-intelligence indicators (URLs, domains, IP addresses,
SSL certificates, DNS records, web content) and presents them as a
unified, evidence-based risk assessment.

> All sources used here are **ethical and public** — WHOIS, DNS, RDAP,
> crt.sh, PhishTank, VirusTotal, urlscan.io, AbuseIPDB, IP-API.

---

## Architecture

```
                ┌──────────────────────────────┐
                │        Web dashboard         │
                │  (FastAPI + Jinja2 + JS)     │
                └──────────────┬───────────────┘
                               │ HTTP / REST
                ┌──────────────▼───────────────┐
                │       Investigator           │
                │  (orchestrator + scorer)     │
                └──────────────┬───────────────┘
       ┌──────────┬──────────┬─┴──────┬──────────────┬──────────────┐
       ▼          ▼          ▼        ▼              ▼              ▼
   URL lex.   WHOIS/RDAP   DNS     SSL/TLS       Content       Reputation
                            │         │              │              │
                            ▼         ▼              ▼              ▼
                            Host IP   TLS cert       PhishTank   VirusTotal
                                                       │         urlscan.io
                                                       ▼
                                              AbuseIPDB / IPinfo
```

### Project layout

```
.
├── app.py                      FastAPI entry point
├── config.py                   Configuration & API keys
├── requirements.txt
├── core/
│   ├── models.py               Pydantic models
│   ├── database.py             SQLite persistence
│   ├── investigator.py         Orchestrator
│   ├── scoring.py              Risk scoring engine
│   ├── correlator.py           IOC correlation
│   └── report.py               JSON / MD / PDF reports
├── collectors/
│   ├── base.py                 Base collector (HTTP session)
│   ├── url_collector.py        URL lexical analysis
│   ├── domain_collector.py     WHOIS / RDAP
│   ├── dns_collector.py        DNS records + SPF/DMARC/DKIM
│   ├── ip_collector.py         IP geolocation + reputation
│   ├── ssl_collector.py        TLS handshake + Certificate Transparency
│   ├── content_collector.py    Web content / redirect chain
│   └── reputation_collector.py PhishTank / VirusTotal / urlscan.io
├── templates/                  HTML pages
├── static/                     CSS + JS
├── reports/                    Generated artefacts
└── tests/                      Pytest suite
```

---

## Quick start

```bash
# 1. install dependencies
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

# 2. (optional) set API keys to enable richer sources
set VIRUSTOTAL_API_KEY=...      # Windows
set ABUSEIPDB_API_KEY=...
set URLSCAN_API_KEY=...
set IPINFO_API_KEY=...
set PHISHTANK_API_KEY=...

# 3. run the server
uvicorn app:app --reload --port 8000
```

Open <http://localhost:8000> in a browser.

### Submitting an investigation

* Web UI: <http://localhost:8000/investigate>
* REST:    `POST /api/investigate` with `{"target": "https://example.com/login"}`

### Available endpoints

| Method | Path                                      | Description                       |
|-------:|-------------------------------------------|-----------------------------------|
| GET    | `/`                                       | Dashboard                         |
| GET    | `/investigate`                            | Investigation form                |
| GET    | `/report/{id}`                            | Saved report                      |
| GET    | `/history`                                | Past investigations               |
| POST   | `/api/investigate`                        | Run an investigation              |
| GET    | `/api/investigations`                     | List investigations               |
| GET    | `/api/investigations/{id}`                | Get a single investigation        |
| GET    | `/api/investigations/{id}/report`         | Export JSON / Markdown / PDF      |
| GET    | `/api/ioc/search?value=...`               | IOC cross-search                  |
| GET    | `/api/stats`                              | Dashboard statistics              |
| GET    | `/docs`                                   | OpenAPI / Swagger UI              |

---

## Risk scoring

The score is a weighted sum of the following evidence, capped at 100:

| Source      | Indicator                                | Points |
|-------------|------------------------------------------|-------:|
| URL         | Suspicious keyword in URL                |   5+   |
| URL         | Brand impersonation keyword              |  10+   |
| URL         | IP host (literal IPv4)                   |  15    |
| URL         | Punycode (homograph risk)                |  10    |
| URL         | Risky TLD (`.zip`, `.tk`, `.xyz`, …)     |  6-14  |
| URL         | Excessive subdomain depth                |   8    |
| Domain      | Created < 30 days ago                    |  10    |
| Domain      | No nameservers                           |   5    |
| Domain      | Privacy-protected registrant + young     |   4    |
| DNS         | Missing SPF / DMARC / DKIM               | 4-10   |
| DNS         | No MX records                            |   6    |
| IP          | AbuseIPDB confidence ≥ 50                |  20    |
| IP          | Tor / proxy                              |  5-8   |
| SSL         | Self-signed or expired                   |  8-12  |
| SSL         | Hostname mismatch                        |  15    |
| Content     | Password / credit card input             | 12-15  |
| Content     | Brand impersonation on page              |  10+   |
| Content     | Excessive redirect chain                |   8    |
| Reputation  | PhishTank verified hit                   |  30    |
| Reputation  | VirusTotal malicious engines             |  7×n   |
| Reputation  | VirusTotal suspicious engines            |  3×n   |

The total score maps to a verdict:

| Score     | Risk level      | Verdict           |
|----------:|-----------------|-------------------|
|  0 – 9    | informational   | unknown           |
| 10 – 29   | low             | benign            |
| 30 – 54   | medium          | suspicious        |
| 55 – 74   | high            | likely_phishing   |
| 75 – 100  | critical        | phishing          |

---

## Correlation engine

Beyond individual scores, the correlator surfaces patterns that
become visible only when evidence is combined:

* Newly registered domain hosted on a malicious IP
* Brand keyword in URL served by a self-signed certificate
* PhishTank hit + missing DMARC
* Multi-engine detection + credential capture form
* Tor exit + password input

---

## Configuration

All keys are optional. The platform works stand-alone using only
WHOIS / RDAP / DNS / TLS / Certificate Transparency / IP-API.

| Environment variable | Source                                            |
|----------------------|---------------------------------------------------|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 (URL, IP, domain)                   |
| `ABUSEIPDB_API_KEY`  | AbuseIPDB IP reputation                           |
| `URLSCAN_API_KEY`    | urlscan.io live submission / scan reports         |
| `IPINFO_API_KEY`     | ipinfo.io (raises the rate-limit)                 |
| `PHISHTANK_API_KEY`  | PhishTank (optional app key for higher rate)      |
| `OSINT_DB_PATH`      | SQLite path (default `./data/investigations.db`)  |
| `OSINT_REPORTS_DIR`  | Artefact directory (default `./reports`)          |
| `OSINT_HTTP_TIMEOUT` | Per-request timeout                              |

---

## Tests

```bash
python -m pytest tests/ -v
```

The unit tests cover scoring, correlation, report rendering and
the database layer. The investigator is exercised with mocked
collectors so the suite remains offline.

---

## Ethical use

Only public OSINT sources are queried. No credentials are sent to
the target infrastructure beyond a standard HTTP GET / TLS handshake.
Do not point the platform at systems you do not own or have
explicit permission to investigate.
