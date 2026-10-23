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

import html
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding, RawTechnology
from .registry import register_scanner

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

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
    category = "web"
    label = "Security headers"
    description = (
        "Checks the site's HTTP response for missing security headers and notes the server technology."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.MISSING_HEADER]

    TIMEOUT_SECONDS = 10
    # The <title> is near the top; no need to download the whole page.
    TITLE_BYTES = 64 * 1024

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

    def extract_asset_facts(self, target) -> dict:
        self._fetch_headers(target.value)
        page = getattr(self, "_page", None)
        return {"web": page} if page else {}

    def _fetch_headers(self, host: str):
        # Cached per instance-call to avoid double-fetching between run(),
        # extract_technologies() and extract_asset_facts() within the same scan.
        if getattr(self, "_headers_cache", {}).get(host) is not None:
            return self._headers_cache[host]

        url = f"https://{host}"
        request = urllib.request.Request(url, headers={"User-Agent": "asm-platform-httpx/1.0"})
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.TIMEOUT_SECONDS) as response:
                headers, status, final_url = response.headers, response.status, response.geturl()
                body = response.read(self.TITLE_BYTES)
        except urllib.error.HTTPError as exc:
            # The server responded -- even with 403/404/5xx -- which means
            # it's reachable and the response headers are real data, not
            # a scan failure. WAF/bot-protection commonly 403s unrecognized
            # clients; that's a legitimate finding, not an error to retry.
            headers, status, final_url = exc.headers, exc.code, exc.geturl() or url
            body = exc.read(self.TITLE_BYTES) if exc.fp else b""
        except (urllib.error.URLError, TimeoutError) as exc:
            # Genuine failure to reach the host at all (DNS, connection
            # refused, timeout) -- this one IS worth retrying.
            raise RuntimeError(f"httpx scan of {host} failed: {exc}") from exc

        self._page = {
            "status": status,
            "title": page_title(body),
            "final_url": final_url,
            "response_ms": round((time.monotonic() - started) * 1000),
            "server": headers.get("Server", "") or "",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        self._headers_cache = {host: headers}
        return headers


def page_title(body: bytes) -> str:
    """The <title> of an HTML page, tidied; "" when there isn't one."""
    match = TITLE_RE.search(body.decode("utf-8", errors="replace"))
    if not match:
        return ""
    return " ".join(html.unescape(match.group(1)).split())[:200]
