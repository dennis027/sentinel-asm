"""
Will the domain's nameservers hand over the whole DNS zone to anyone?

A zone transfer (AXFR) is how DNS servers copy a zone between
themselves. A server that grants it to strangers gives away every
hostname the organization has in one reply -- internal names, staging
systems, forgotten services -- which is the map an attacker would
otherwise have to work for.

Organization-level: asked once per nameserver of the root domain. The
records themselves are not kept, only how many came back.
"""

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from apps.findings.models import Finding

from ..targets import TargetNotAllowed, assert_public_target
from .base import BaseScanner, RawFinding
from .registry import register_scanner

MAX_NAMESERVERS = 6


@register_scanner
class DnsZoneTransferScanner(BaseScanner):
    name = "dns_zone_transfer"
    category = "network"
    label = "DNS zone transfer"
    description = (
        "Checks whether your nameservers will give your complete list of hostnames to anyone who asks."
    )
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.ZONE_TRANSFER]

    TIMEOUT_SECONDS = 6

    def run(self, target) -> list[RawFinding]:
        domain = target.root_domain
        findings = []
        for nameserver in self._nameservers(domain)[:MAX_NAMESERVERS]:
            record_count = self._transfer(domain, nameserver)
            if record_count is None:
                continue
            findings.append(RawFinding(
                finding_type=Finding.FindingType.ZONE_TRANSFER,
                identifier=nameserver,
                severity=Finding.Severity.HIGH,
                title=f"Nameserver {nameserver} allows zone transfers",
                description=(
                    f"{nameserver} returned the full DNS zone for {domain} ({record_count} names) "
                    "to an unauthenticated request."
                ),
                raw_data={"check": "zone_transfer_allowed", "nameserver": nameserver, "names": record_count},
                asset_value=domain,
            ))
        return findings

    def _resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = self.TIMEOUT_SECONDS
        return resolver

    def _nameservers(self, domain: str) -> list[str]:
        try:
            answers = self._resolver().resolve(domain, "NS")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.exception.DNSException as exc:
            raise RuntimeError(f"Could not look up nameservers for {domain}: {exc}") from exc
        return sorted(answer.target.to_text().rstrip(".") for answer in answers)

    def _transfer(self, domain: str, nameserver: str) -> int | None:
        """Number of names in the zone if the transfer is granted, else None."""
        try:
            assert_public_target(nameserver)
            address = self._resolver().resolve(nameserver, "A")[0].to_text()
            zone = dns.zone.from_xfr(
                dns.query.xfr(address, domain, timeout=self.TIMEOUT_SECONDS, lifetime=self.TIMEOUT_SECONDS * 2)
            )
        except (TargetNotAllowed, dns.exception.DNSException, OSError, EOFError):
            # Refused, timed out, not answering on TCP: all mean "no".
            return None
        return len(zone.nodes)
