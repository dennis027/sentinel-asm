"""
Security-header audit + basic tech fingerprinting over HTTPS.

Pure standard-library (urllib) implementation, same philosophy as
ssl_expiry: no external binary or image dependency for this one. Tech
detection here is intentionally simple (Server/X-Powered-By header
parsing) rather than a full Wappalyzer-style fingerprint database --
documented trade-off, upgradeable later to the real `httpx` binary
(ProjectDiscovery) with -td if deeper detection is worth the added
image size.
"""

import urllib.error
import urllib.request

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding, RawTechnology
from .registry import register_scanner

# header -> (display name, severity if missing)
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS", Finding.Severity.MEDIUM),
    "Content-Security-Policy": ("CSP", Finding.Severity.MEDIUM),
    "X-Content-Type-Options": ("X-Content-Type-Options", Finding.Severity.LOW),
    "X-Frame-Options": ("X-Frame-Options", Finding.Severity.LOW),
    "Referrer-Policy": ("Referrer-Policy", Finding.Severity.INFO),
}


@register_scanner
class HttpxScanner(BaseScanner):
    name = "httpx"
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.MISSING_HEADER]

    TIMEOUT_SECONDS = 10

    def run(self, target) -> list[RawFinding]:
        headers = self._fetch_headers(target.value)
        return [
            RawFinding(
                finding_type=Finding.FindingType.MISSING_HEADER,
                identifier=f"missing:{header_name}",
                severity=severity,
                title=f"Missing security header: {display_name}",
                description=(
                    f"{target.value} does not set the {header_name} header, "
                    f"which helps protect against common web attacks."
                ),
                raw_data={"header": header_name},
            )
            for header_name, (display_name, severity) in SECURITY_HEADERS.items()
            # .get() on an HTTPMessage is case-insensitive (headers are
            # case-insensitive per RFC 7230) -- don't convert to a plain
            # dict and use `in`, that silently breaks this check whenever
            # a server sends e.g. "strict-transport-security" lowercase.
            if headers.get(header_name) is None
        ]

    def extract_technologies(self, target) -> list[RawTechnology]:
        headers = self._fetch_headers(target.value)
        technologies = []

        if server := headers.get("Server"):
            technologies.append(RawTechnology(name=server, category="web-server"))
        if powered_by := headers.get("X-Powered-By"):
            technologies.append(RawTechnology(name=powered_by, category="framework"))

        return technologies

    def _fetch_headers(self, host: str):
        # Cached per instance-call to avoid double-fetching between run()
        # and extract_technologies() within the same scan.
        if hasattr(self, "_headers_cache") and self._headers_cache.get(host) is not None:
            return self._headers_cache[host]

        url = f"https://{host}"
        request = urllib.request.Request(url, headers={"User-Agent": "asm-platform-httpx/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=self.TIMEOUT_SECONDS) as response:
                # Keep the original email.message.Message object -- its
                # .get() is case-insensitive, which plain dict() is not.
                headers = response.headers
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            raise RuntimeError(f"httpx scan of {host} failed: {exc}") from exc

        self._headers_cache = {host: headers}
        return headers