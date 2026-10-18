"""
The DNS settings security ratings look at, beyond email:

- CAA: which certificate authorities may issue certificates for the
  domain. Without it, any of the hundreds of public CAs can.
- DNSSEC: signs the domain's records so they can't be forged in transit.
- Wildcard DNS: every made-up name resolves, which hides real hosts from
  inventory and makes subdomain takeover and phishing easier.
- Nameserver redundancy: a single nameserver is a single point of failure.

DNS lookups only; organization-level, filed on the root domain.
"""

import secrets

import dns.exception
import dns.resolver

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

S = Finding.Severity


@register_scanner
class DnsHygieneScanner(BaseScanner):
    name = "dns_hygiene"
    category = "email_domain"
    label = "DNS hygiene"
    description = "Checks CAA, DNSSEC, wildcard records and nameserver redundancy for your domain."
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.DNS_HYGIENE]

    TIMEOUT = 5

    def run(self, target) -> list[RawFinding]:
        domain = target.root_domain
        findings = []

        def add(check, severity, title, description, **raw):
            findings.append(RawFinding(
                finding_type=Finding.FindingType.DNS_HYGIENE, identifier=check, severity=severity,
                title=f"{title} for {domain}", description=description,
                raw_data={"check": check, "domain": domain, **raw}, asset_value=domain,
            ))

        if not self._records(domain, "CAA"):
            add("caa_missing", S.LOW, "No CAA record",
                "The domain publishes no CAA record, so any public certificate authority may issue certificates for it.")
        if not self._records(domain, "DNSKEY"):
            add("dnssec_missing", S.LOW, "DNSSEC is not enabled",
                "The domain's DNS records are not signed, so a resolver can't tell a forged answer from a real one.")
        if self._records(f"densight-{secrets.token_hex(5)}.{domain}", "A"):
            add("wildcard_dns", S.LOW, "Wildcard DNS is in use",
                "Every name under the domain resolves, including ones nobody created.")
        nameservers = self._records(domain, "NS")
        if len(nameservers) == 1:
            add("single_nameserver", S.MEDIUM, "Only one nameserver",
                f"The domain is served by a single nameserver ({nameservers[0]}); if it fails, the domain disappears.",
                nameservers=nameservers)
        return findings

    def _records(self, name: str, record_type: str) -> list[str]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = self.TIMEOUT
        try:
            return sorted(answer.to_text().rstrip(".") for answer in resolver.resolve(name, record_type))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.exception.DNSException as exc:
            # Not knowing is not the same as "missing": don't report on a timeout.
            raise RuntimeError(f"DNS lookup for {name} {record_type} failed: {exc}") from exc
