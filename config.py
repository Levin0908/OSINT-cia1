"""Application configuration loaded from environment variables.

All API keys are optional. The application will gracefully degrade
when a key is not provided, simply skipping the OSINT source.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# --- HTTP / networking -------------------------------------------------------
HTTP_TIMEOUT = int(os.getenv("OSINT_HTTP_TIMEOUT", "15"))
HTTP_USER_AGENT = os.getenv(
    "OSINT_USER_AGENT",
    "OSINT-Phishing-Investigator/1.0 (+research; ethical OSINT only)"
)
HTTP_MAX_REDIRECTS = int(os.getenv("OSINT_MAX_REDIRECTS", "10"))

# --- Persistence -------------------------------------------------------------
DB_PATH = os.getenv("OSINT_DB_PATH", str(BASE_DIR / "data" / "investigations.db"))
REPORTS_DIR = os.getenv("OSINT_REPORTS_DIR", str(BASE_DIR / "reports"))
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)

# --- Optional API keys (free-tier / community) -------------------------------
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY", "").strip()
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()

# --- Endpoints ---------------------------------------------------------------
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"
URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_IP = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VIRUSTOTAL_DOMAIN = "https://www.virustotal.com/api/v3/domains/{domain}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
IPINFO_URL = "https://ipinfo.io/{ip}/json"
RDAP_URL = "https://rdap.org/"
CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"
IPAPI_URL = "http://ip-api.com/json/{ip}"

# --- Risk scoring weights ----------------------------------------------------
WEIGHT_URL_AGE = 5
WEIGHT_DOMAIN_AGE = 10
WEIGHT_SSL_SELF_SIGNED = 8
WEIGHT_SSL_EXPIRED = 12
WEIGHT_SSL_MISMATCH = 15
WEIGHT_NO_HTTPS = 6
WEIGHT_REDIRECT_CHAIN = 8
WEIGHT_SUSPICIOUS_KEYWORDS = 10
WEIGHT_TLD_RISK = 12
WEIGHT_IP_REP = 20
WEIGHT_PHISHTANK_HIT = 30
WEIGHT_VT_DETECTIONS = 25
WEIGHT_ABUSEIPDB = 18
WEIGHT_DNS_MX_MISSING = 6
WEIGHT_DMARC_MISSING = 10
WEIGHT_WHOIS_HIDDEN = 4
WEIGHT_EXTERNAL_RESOURCE = 7


def get(name: str, default: str = "") -> str:
    """Safe lookup for optional configuration constants."""
    return os.getenv(name, default)
