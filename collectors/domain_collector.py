"""Domain / WHOIS information via RDAP (Registration Data Access Protocol).

RDAP is the IETF successor to WHOIS. The public RDAP bootstrap at
https://rdap.org/ resolves the right registry for any TLD and returns
machine-readable JSON. Falls back to the legacy WHOIS protocol as a
last resort.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import tldextract
import whois

import config
from collectors.base import BaseCollector
from core.models import DomainFeatures, IOC

logger = logging.getLogger(__name__)


def _coerce_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
    return None


class DomainCollector(BaseCollector):
    name = "domain"
    description = "WHOIS / RDAP registration data"

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        ext = tldextract.extract(target)
        domain = ext.registered_domain or target
        if not domain or "." not in domain:
            return {"domain": None}

        text = self._rdap_lookup(domain)
        result = self._parse_rdap(text, domain, ext) if text else None
        if not result:
            result = self._whois_lookup(domain, ext)
        return {"domain": result}

    # ------------------------------------------------------------------
    # RDAP
    # ------------------------------------------------------------------
    def _rdap_lookup(self, domain: str) -> Optional[str]:
        try:
            resp = self.session.get(
                config.RDAP_URL + domain,
                headers={"Accept": "application/rdap+json"},
                timeout=self.timeout,
            )
            if resp is None or resp.status_code != 200:
                return None
            return resp.text
        except Exception as exc:
            self._log_error(f"rdap {domain}", exc)
            return None

    def _parse_rdap(self, text: str, domain: str, ext: Any) -> Optional[DomainFeatures]:
        import json
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        events = {e.get("event"): _coerce_dt(e.get("date")) for e in data.get("events", [])}
        entities = data.get("entities", [])
        registrar = None
        registrant = None
        registrant_country = None
        for entity in entities:
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [None, []])[1]
            name = None
            org = None
            country = None
            for item in vcard:
                if item[0] == "fn":
                    name = item[3]
                elif item[0] == "org":
                    org = item[3]
                elif item[0] == "adr":
                    try:
                        country = item[3][6]
                    except (IndexError, TypeError):
                        pass
            if "registrar" in roles:
                registrar = org or name
            if "registrant" in roles:
                if org:
                    registrant = org
                elif name:
                    registrant = name
                registrant_country = country
        statuses = data.get("status", [])
        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
        creation = events.get("registration")
        expiration = events.get("expiration")
        updated = events.get("last changed") or events.get("last update")
        age_days = (datetime.now(timezone.utc) - creation).days if creation else None
        return DomainFeatures(
            domain=domain,
            tld=ext.suffix or "",
            sld=ext.domain or "",
            creation_date=creation,
            expiration_date=expiration,
            updated_date=updated,
            registrar=registrar,
            registrant=registrant,
            registrant_country=registrant_country,
            name_servers=nameservers,
            statuses=statuses,
            age_days=age_days,
            is_private=bool(registrar and "privacy" in (registrar or "").lower()
                            or "redacted" in (registrant or "").lower()
                            or "whoisguard" in (registrant or "").lower()),
        )

    # ------------------------------------------------------------------
    # WHOIS fallback
    # ------------------------------------------------------------------
    def _whois_lookup(self, domain: str, ext: Any) -> Optional[DomainFeatures]:
        try:
            w = whois.whois(domain)
        except Exception as exc:
            self._log_error(f"whois {domain}", exc)
            return None
        if not w or not w.domain_name:
            return None
        creation = _coerce_dt(w.creation_date)
        expiration = _coerce_dt(w.expiration_date)
        updated = _coerce_dt(w.updated_date)
        name_servers = list(w.name_servers or [])
        if name_servers and isinstance(name_servers[0], str):
            name_servers = [n.lower() for n in name_servers]
        registrant = None
        if isinstance(w.get("name"), str):  # type: ignore[attr-defined]
            registrant = w.get("name")  # type: ignore[attr-defined]
        registrar = getattr(w, "registrar", None)
        age_days = (datetime.now(timezone.utc) - creation).days if creation else None
        return DomainFeatures(
            domain=domain,
            tld=ext.suffix or "",
            sld=ext.domain or "",
            creation_date=creation,
            expiration_date=expiration,
            updated_date=updated,
            registrar=registrar,
            registrant=registrant,
            registrant_country=getattr(w, "country", None),
            name_servers=name_servers,
            statuses=list(getattr(w, "status", []) or []),
            age_days=age_days,
            is_private=bool(registrar and "privacy" in (registrar or "").lower()),
        )

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        dom: Optional[DomainFeatures] = payload.get("domain")
        if not dom:
            return []
        iocs: List[IOC] = [IOC(
            type="domain",
            value=dom.domain,
            source=self.name,
            malicious=False,
            confidence=0,
            tags=[f"age:{dom.age_days}d" if dom.age_days is not None else "age:unknown",
                  "private" if dom.is_private else "public"],
        )]
        for ns in dom.name_servers[:5]:
            iocs.append(IOC(type="nameserver", value=ns.lower(), source=self.name))
        return iocs
