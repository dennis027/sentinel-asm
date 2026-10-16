"""
Is the site still reachable over unencrypted HTTP?

Having HTTPS is not enough if the plain-HTTP address also serves the
site: anyone who types the address without "https://", or follows an
old link, sends and receives everything in the clear, where others on
the same network can read or alter it.

A correctly set up site answers HTTP with nothing but a redirect to
HTTPS. This scanner makes one plain-HTTP request and looks at the reply.
"""

from urllib.parse import urlsplit

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner


def assess(host: str, http_status: int, location: str | None, https_works: bool) -> RawFinding | None:
    """Pure function: the plain-HTTP reply (and whether HTTPS answers) -> a finding, or None."""
    redirects_to_https = 300 <= http_status < 400 and urlsplit(location or "").scheme == "https"
    if redirects_to_https:
        return None

    if not https_works:
        return RawFinding(
            finding_type=Finding.FindingType.NO_HTTPS,
            identifier="https",
            severity=Finding.Severity.HIGH,
            title="Site is only available over unencrypted HTTP",
            description=f"{host} answers on plain HTTP and does not offer HTTPS at all.",
            raw_data={"check": "http_only", "http_status": http_status},
        )
    return RawFinding(
        finding_type=Finding.FindingType.NO_HTTPS,
        identifier="https",
        severity=Finding.Severity.MEDIUM,
        title="Site does not redirect HTTP to HTTPS",
        description=(
            f"{host} serves content over plain HTTP (status {http_status}) instead of sending "
            "visitors to the HTTPS version."
        ),
        raw_data={"check": "no_https_redirect", "http_status": http_status},
    )


@register_scanner
class HttpsEnforcementScanner(BaseScanner):
    name = "https_enforcement"
    category = "encryption"
    label = "HTTPS enforcement"
    description = "Checks that the unencrypted HTTP address only redirects visitors to HTTPS."
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.NO_HTTPS]

    def run(self, target) -> list[RawFinding]:
        host = target.value
        try:
            plain = fetch(host, schemes=("http",), follow_redirects=False)
        except RuntimeError:
            return []  # nothing answers on plain HTTP: nothing to enforce

        try:
            fetch(host, schemes=("https",), follow_redirects=False)
            https_works = True
        except RuntimeError:
            https_works = False

        finding = assess(host, plain.status, plain.headers.get("Location"), https_works)
        return [finding] if finding else []
