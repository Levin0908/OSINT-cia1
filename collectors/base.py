"""Abstract base class for OSINT collectors.

Every collector follows the same lifecycle:

1. ``collect(target)``         -> runs all external lookups
2. ``normalize(result)``       -> converts raw data into Pydantic models
3. ``extract_iocs(result)``    -> returns a list of IOC objects

A collector must never raise; it should swallow network errors and
return whatever evidence it managed to gather. Errors are forwarded
to the orchestrator so the analyst can see what failed.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import config
from core.models import IOC

logger = logging.getLogger(__name__)

T = TypeVar("T")


class BaseCollector:
    """Reusable HTTP session with retries and a friendly UA."""

    name: str = "base"
    description: str = ""

    def __init__(self, timeout: int = config.HTTP_TIMEOUT) -> None:
        self.timeout = timeout
        self.errors: List[str] = []
        self.session = self._build_session()

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _build_session(self) -> requests.Session:
        sess = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST", "HEAD"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        sess.headers.update(
            {
                "User-Agent": config.HTTP_USER_AGENT,
                "Accept": "application/json, text/html;q=0.9, */*;q=0.5",
            }
        )
        return sess

    def get(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            self._log_error(f"GET {url}", exc)
            return None

    def post(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        try:
            return self.session.post(url, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            self._log_error(f"POST {url}", exc)
            return None

    def head(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        try:
            return self.session.head(url, timeout=self.timeout, allow_redirects=True, **kwargs)
        except requests.RequestException as exc:
            self._log_error(f"HEAD {url}", exc)
            return None

    def _log_error(self, where: str, exc: Exception) -> None:
        msg = f"{self.name}: {where} failed: {exc}"
        logger.warning(msg)
        self.errors.append(msg)

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Run the collector. Subclasses should override this."""
        return {}

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        """Convert the normalised payload into IOC objects."""
        return []

    def is_available(self) -> bool:
        """Override to indicate that an API key is required."""
        return True
