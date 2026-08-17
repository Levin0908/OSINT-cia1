"""SSL/TLS certificate inspection via direct TLS handshake.

Also queries crt.sh (public Certificate Transparency log) for the
complete set of certificates ever issued for a domain. crt.sh is
operated by Sectigo and freely accessible.
"""
from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import config
from collectors.base import BaseCollector
from core.models import IOC, SslFeatures


class SslCollector(BaseCollector):
    name = "ssl"
    description = "SSL/TLS certificate inspection (handshake + Certificate Transparency)"

    def collect(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        host = context.get("hostname") or target
        port = int(context.get("port") or 443)
        if not host:
            return {"ssl": None}

        features = self._tls_inspect(host, port) or SslFeatures()
        ct_count = self._crt_sh_count(host)
        if ct_count is not None:
            features = features.model_copy(update={"ct_log_hits": ct_count})
        return {"ssl": features}

    # ------------------------------------------------------------------
    # TLS handshake
    # ------------------------------------------------------------------
    def _tls_inspect(self, host: str, port: int) -> Optional[SslFeatures]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    if not der:
                        return None
                    cert_dict = ssock.getpeercert()
                    cipher = ssock.cipher()
        except Exception as exc:
            self._log_error(f"tls {host}:{port}", exc)
            return None

        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert = x509.load_der_x509_certificate(der, default_backend())
            cn = ""
            try:
                cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # type: ignore
            except Exception:
                pass
            issuer = cert.issuer.rfc4514_string()
            sigalg = cert.signature_algorithm_oid._name  # type: ignore[attr-defined]
            key_size = getattr(cert.public_key(), "key_size", 0)  # type: ignore[attr-defined]
            not_before = cert.not_valid_before_utc  # type: ignore[attr-defined]
            not_after = cert.not_valid_after_utc  # type: ignore[attr-defined]
            serial = format(cert.serial_number, "x")
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                alt_names = [str(name) for name in san_ext.value]  # type: ignore[attr-defined]
            except Exception:
                alt_names = []
        except Exception as exc:
            self._log_error(f"der parse {host}", exc)
            return None

        now = datetime.now(timezone.utc)
        valid_for_host = host.lower() in [a.lower() for a in alt_names] or host.lower() == cn.lower()
        features = SslFeatures(
            subject=f"CN={cn}",
            issuer=issuer,
            common_name=cn,
            alt_names=alt_names,
            not_before=not_before,
            not_after=not_after,
            days_remaining=(not_after - now).days,
            self_signed=(issuer.lower() == cert.subject.rfc4514_string().lower()),
            expired=not_after < now,
            valid_for_host=valid_for_host,
            serial_number=serial,
            signature_algorithm=sigalg,
            key_size=key_size,
        )
        return features

    # ------------------------------------------------------------------
    # Certificate Transparency
    # ------------------------------------------------------------------
    def _crt_sh_count(self, domain: str) -> Optional[int]:
        resp = self.get(config.CRT_SH_URL.format(domain=domain))
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        return len(data) if isinstance(data, list) else None

    def extract_iocs(self, payload: Dict[str, Any]) -> List[IOC]:
        ssl: Optional[SslFeatures] = payload.get("ssl")
        if not ssl:
            return []
        malicious = ssl.self_signed or ssl.expired or not ssl.valid_for_host
        confidence = 0
        if ssl.self_signed:
            confidence += 50
        if ssl.expired:
            confidence += 40
        if not ssl.valid_for_host:
            confidence += 60
        return [IOC(
            type="ssl",
            value=f"CN={ssl.common_name} issuer={ssl.issuer}",
            source=self.name,
            malicious=malicious,
            confidence=min(100, confidence),
            tags=[
                "self_signed" if ssl.self_signed else "issuer_ok",
                "expired" if ssl.expired else f"valid_for_{ssl.days_remaining}d",
                "mismatch" if not ssl.valid_for_host else "host_match",
            ],
        )]
