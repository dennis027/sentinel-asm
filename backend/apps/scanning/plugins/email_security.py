"""
Can someone send email that appears to come from this domain?

Reads the three DNS records that decide it -- SPF, DMARC and (as far as
it can be seen from outside) DKIM -- and reports what is missing or too
permissive. DNS lookups only: nothing connects to the organization's
servers, so this is the lightest scanner there is.

Organization-level: email authentication is set on the root domain, so
it runs once per organization and files its findings on the root
domain's asset.
"""

from dataclasses import dataclass

import dns.exception
import dns.resolver

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

# There is no way to list a domain's DKIM selectors; these are the
# names the big mail providers use, which covers most setups.
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim", "smtp", "mandrill", "mxvault",
]


@dataclass
class Issue:
    check: str
    severity: str
    title: str
    description: str


def evaluate_spf(txt_records: list[str]) -> list[Issue]:
    """SPF says which servers may send mail for the domain."""
    spf = [record for record in txt_records if record.lower().startswith("v=spf1")]
    if not spf:
        return [Issue(
            "spf_missing", Finding.Severity.MEDIUM, "No SPF record",
            "The domain publishes no SPF record, so receiving mail servers have no list of "
            "servers allowed to send its email.",
        )]
    if len(spf) > 1:
        return [Issue(
            "spf_multiple", Finding.Severity.MEDIUM, "More than one SPF record",
            f"The domain publishes {len(spf)} SPF records. Receivers treat that as an error and "
            "ignore all of them.",
        )]

    terms = spf[0].lower().split()
    all_term = next((term for term in terms if term.lstrip("+-~?") == "all"), None)
    if all_term in ("all", "+all"):
        return [Issue(
            "spf_allows_anyone", Finding.Severity.HIGH, "SPF record allows any server to send",
            f"The SPF record ends in '{all_term}', which authorises every server on the internet "
            "to send email for this domain.",
        )]
    if all_term == "?all":
        return [Issue(
            "spf_neutral", Finding.Severity.LOW, "SPF record does not reject other senders",
            "The SPF record ends in '?all' (neutral): mail from servers that are not listed is "
            "treated the same as mail from servers that are.",
        )]
    if all_term is None and not any(term.startswith("redirect=") for term in terms):
        return [Issue(
            "spf_no_all", Finding.Severity.LOW, "SPF record has no 'all' rule",
            "The SPF record lists allowed servers but never says what to do with the rest, so "
            "unlisted senders are not rejected.",
        )]
    return []


def evaluate_dmarc(txt_records: list[str]) -> list[Issue]:
    """DMARC tells receivers what to do with mail that fails SPF and DKIM."""
    dmarc = [record for record in txt_records if record.lower().startswith("v=dmarc1")]
    if not dmarc:
        return [Issue(
            "dmarc_missing", Finding.Severity.HIGH, "No DMARC record",
            "The domain publishes no DMARC record. Receiving mail servers are given no instruction "
            "to reject messages that fake this domain in the From address.",
        )]
    if len(dmarc) > 1:
        return [Issue(
            "dmarc_multiple", Finding.Severity.MEDIUM, "More than one DMARC record",
            f"The domain publishes {len(dmarc)} DMARC records. Receivers ignore DMARC entirely "
            "when there is more than one.",
        )]

    tags = {}
    for part in dmarc[0].split(";"):
        name, _, value = part.strip().partition("=")
        tags[name.strip().lower()] = value.strip().lower()

    policy = tags.get("p", "")
    if policy not in ("quarantine", "reject"):
        return [Issue(
            "dmarc_monitor_only", Finding.Severity.MEDIUM, "DMARC policy is monitor-only",
            f"The DMARC policy is 'p={policy or 'none'}': forged messages are reported but still "
            "delivered.",
        )]
    try:
        percent = int(tags.get("pct", "100"))
    except ValueError:
        percent = 100
    if percent < 100:
        return [Issue(
            "dmarc_partial", Finding.Severity.LOW, f"DMARC policy applies to only {percent}% of mail",
            f"The DMARC record sets pct={percent}, so the policy is skipped for the remaining "
            f"{100 - percent}% of forged messages.",
        )]
    return []


@register_scanner
class EmailSecurityScanner(BaseScanner):
    name = "email_security"
    category = "email_domain"
    label = "Email spoofing protection"
    description = (
        "Checks the SPF, DKIM and DMARC records that stop other people sending email as your domain."
    )
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.EMAIL_SECURITY]

    TIMEOUT_SECONDS = 5

    def run(self, target) -> list[RawFinding]:
        domain = target.root_domain
        issues = evaluate_spf(self._txt(domain)) + evaluate_dmarc(self._txt(f"_dmarc.{domain}"))

        if not any(self._txt(f"{selector}._domainkey.{domain}", tolerate_errors=True)
                   for selector in COMMON_DKIM_SELECTORS):
            issues.append(Issue(
                "dkim_not_found", Finding.Severity.INFO, "DKIM signing could not be confirmed",
                "No DKIM key was found under the selector names commonly used by mail providers. "
                "The domain may still sign its mail under a custom selector that cannot be "
                "discovered from outside.",
            ))

        return [
            RawFinding(
                finding_type=Finding.FindingType.EMAIL_SECURITY,
                identifier=issue.check,
                severity=issue.severity,
                title=f"{issue.title} for {domain}",
                description=issue.description,
                raw_data={"check": issue.check, "domain": domain},
                asset_value=domain,
            )
            for issue in issues
        ]

    def _txt(self, name: str, tolerate_errors: bool = False) -> list[str]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = self.TIMEOUT_SECONDS
        try:
            answers = resolver.resolve(name, "TXT")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []  # a real answer: there is no such record
        except dns.exception.DNSException as exc:
            if tolerate_errors:
                return []
            # Not knowing is different from "missing": don't report a
            # missing SPF record because a resolver timed out.
            raise RuntimeError(f"DNS lookup for {name} failed: {exc}") from exc
        # A TXT record can be split into several strings on the wire.
        return [b"".join(answer.strings).decode("utf-8", "ignore").strip() for answer in answers]
