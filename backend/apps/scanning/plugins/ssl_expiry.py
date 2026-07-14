"""
Checks how many days remain before an asset's TLS certificate expires.

Pure standard-library implementation (ssl + socket) -- no external
binary, no extra image dependency. This is deliberately the first
scanner implemented: it proves the plugin/task/model pipeline end to
end before any subprocess-based tool (nmap, nuclei) is wired in.
"""

import socket
import ssl
from datetime import datetime, timezone

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner


@register_scanner
class SSLExpiryScanner(BaseScanner):
    name = "ssl_expiry"
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.EXPIRED_SSL]

    CRITICAL_DAYS = 0    # already expired
    HIGH_DAYS = 7
    MEDIUM_DAYS = 30

    def run(self, target) -> list[RawFinding]:
        host = target.value
        not_after = self._get_cert_expiry(host)

        days_remaining = (not_after - datetime.now(timezone.utc)).days
        severity = self._severity_for(days_remaining)

        title = (
            f"TLS certificate expired {abs(days_remaining)} days ago"
            if days_remaining < 0
            else f"TLS certificate expires in {days_remaining} days"
        )

        return [
            RawFinding(
                finding_type=Finding.FindingType.EXPIRED_SSL,
                # Constant identifier: one evolving finding per asset for
                # "current cert status", not a new row every scan.
                identifier="cert_expiry",
                severity=severity,
                title=title,
                description=f"Certificate for {host} is valid until {not_after.isoformat()}.",
                raw_data={"not_after": not_after.isoformat(), "days_remaining": days_remaining},
            )
        ]

    @staticmethod
    def _get_cert_expiry(host: str, port: int = 443, timeout: float = 5.0) -> datetime:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        # e.g. 'Nov  1 00:00:00 2026 GMT'
        not_after_str = cert["notAfter"]
        naive = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        return naive.replace(tzinfo=timezone.utc)

    @classmethod
    def _severity_for(cls, days_remaining: int) -> str:
        if days_remaining <= cls.CRITICAL_DAYS:
            return Finding.Severity.CRITICAL
        if days_remaining <= cls.HIGH_DAYS:
            return Finding.Severity.HIGH
        if days_remaining <= cls.MEDIUM_DAYS:
            return Finding.Severity.MEDIUM
        return Finding.Severity.INFO