"""
Does the site let other websites read its responses on a visitor's behalf?

Browsers normally stop a page on one site from reading data from
another. A site opts out of that with CORS headers. Done carelessly --
echoing back whatever origin asks, and allowing cookies with it -- it
means any web page a logged-in user happens to open can silently read
that user's data from this site.

One request with a made-up Origin header; the answer is in the
response headers.
"""

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

# A domain nobody has allow-listed: if this comes back approved, every origin would.
PROBE_ORIGIN = "https://cors-check.sentinel-asm.invalid"


def assess(host: str, allow_origin: str | None, allow_credentials: str | None) -> RawFinding | None:
    """Pure function: the two CORS response headers -> a finding, or None."""
    origin = (allow_origin or "").strip()
    credentials = (allow_credentials or "").strip().lower() == "true"

    def finding(check: str, severity: str, title: str, description: str) -> RawFinding:
        return RawFinding(
            finding_type=Finding.FindingType.CORS,
            identifier="cors",  # one evolving finding per host
            severity=severity,
            title=title,
            description=description,
            raw_data={"check": check, "allow_origin": origin, "allow_credentials": credentials},
        )

    if origin == PROBE_ORIGIN and credentials:
        return finding(
            "cors_any_origin_with_credentials", Finding.Severity.HIGH,
            "Any website can read logged-in users' data (CORS)",
            f"{host} approves cross-site requests from any origin and allows cookies with them.",
        )
    if origin == "null" and credentials:
        return finding(
            "cors_null_origin_with_credentials", Finding.Severity.MEDIUM,
            "CORS trusts the 'null' origin with credentials",
            f"{host} allows credentialed cross-site requests from the 'null' origin, which "
            "sandboxed pages and local files can use.",
        )
    if origin == PROBE_ORIGIN:
        return finding(
            "cors_any_origin", Finding.Severity.LOW, "CORS approves any origin",
            f"{host} echoes back whichever origin asks. Cookies are not allowed with it, so only "
            "content that is public anyway can be read.",
        )
    # "*" without credentials is the normal setting for public content.
    return None


@register_scanner
class CorsScanner(BaseScanner):
    name = "cors"
    category = "web"
    label = "CORS misconfiguration"
    description = (
        "Checks whether other websites are allowed to read data from this one on a visitor's behalf."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.CORS]

    def run(self, target) -> list[RawFinding]:
        try:
            headers = fetch(target.value, headers={"Origin": PROBE_ORIGIN}).headers
        except RuntimeError:
            return []  # no web server here
        finding = assess(
            target.value,
            headers.get("Access-Control-Allow-Origin"),
            headers.get("Access-Control-Allow-Credentials"),
        )
        return [finding] if finding else []
