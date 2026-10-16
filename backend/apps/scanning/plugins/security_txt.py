"""
Does the organization tell security researchers how to reach it?

security.txt (RFC 9116) is a small text file at
/.well-known/security.txt naming a contact for reporting
vulnerabilities. Without one, someone who finds a problem has nowhere
to send it -- and reports that can't be delivered tend to end up
public instead.

Organization-level: one file on the root domain speaks for the whole
organization.
"""

from datetime import datetime, timezone

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

PATHS = ["/.well-known/security.txt", "/security.txt"]


def parse_fields(body: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        fields.setdefault(name.strip().lower(), []).append(value.strip())
    return fields


def assess(domain: str, body: str | None, now: datetime | None = None) -> RawFinding | None:
    """`body` is the file's text, or None if there is no file. Pure function."""
    now = now or datetime.now(timezone.utc)

    def finding(check: str, title: str, description: str) -> RawFinding:
        return RawFinding(
            finding_type=Finding.FindingType.SECURITY_TXT,
            # One evolving finding: "missing" becomes "expired" becomes resolved.
            identifier="security_txt",
            severity=Finding.Severity.LOW,
            title=title,
            description=description,
            raw_data={"check": check, "domain": domain},
            asset_value=domain,
        )

    if body is None:
        return finding(
            "security_txt_missing", f"No security.txt on {domain}",
            f"{domain} does not publish a security.txt file, so there is no stated way to report "
            "a vulnerability to the organization.",
        )

    fields = parse_fields(body)
    if not fields.get("contact"):
        return finding(
            "security_txt_no_contact", f"security.txt on {domain} has no contact",
            "The file exists but has no Contact line, which is the one field it is required to have.",
        )

    for value in fields.get("expires", []):
        try:
            expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            return finding(
                "security_txt_expired", f"security.txt on {domain} has expired",
                f"The file's Expires date ({value}) has passed, so researchers are told not to "
                "trust the contact details in it.",
            )
    return None


@register_scanner
class SecurityTxtScanner(BaseScanner):
    name = "security_txt"
    category = "email_domain"
    label = "Security contact"
    description = (
        "Checks for a security.txt file telling researchers how to report a vulnerability to you."
    )
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.SECURITY_TXT]

    def run(self, target) -> list[RawFinding]:
        domain = target.root_domain
        body = None
        for path in PATHS:
            page = fetch(domain, path)  # RuntimeError if the site is unreachable -> retried
            # Sites that answer every URL with their home page would
            # otherwise look like they have the file.
            is_text = "text/plain" in (page.headers.get("Content-Type") or "").lower()
            if page.status == 200 and is_text:
                body = page.body
                break
        finding = assess(domain, body)
        return [finding] if finding else []
