"""
DNS record monitoring via dnspython.

Design note on how "change detection" works here: the dedupe_key
identifier includes the record's actual value, not just its type
(e.g. "MX:10 mail.example.com", not just "MX"). This means when a
record's value changes, the OLD value's Finding simply stops being
returned this run and gets resolved by the generic reconciliation
logic in tasks.py (same mechanism nmap uses for closed ports), while
the NEW value creates a brand-new Finding with first_seen=now. A DNS
change is therefore visible as "one finding resolved, one appeared" --
no separate history/diff logic needed anywhere, it falls out of the
existing upsert/reconcile pipeline for free.

Each record type is resolved independently and a failure on one type
(NXDOMAIN, no answer, timeout) never fails the whole scan -- DNS
records are commonly incomplete (e.g. no AAAA record) or slow on one
type (large TXT records needing TCP fallback) without that meaning
anything is actually wrong.
"""

from datetime import datetime, timezone

import dns.exception
import dns.rdatatype
import dns.resolver
import dns.reversename

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]


@register_scanner
class DnsMonitorScanner(BaseScanner):
    name = "dns_monitor"
    category = "discovery"
    label = "DNS records"
    description = (
        "Records the host's DNS entries so changes show up as new and resolved findings."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.DNS_CHANGE]
    # NXDOMAIN is a result here: the records it had are now gone.
    needs_address = False

    TIMEOUT_SECONDS = 5

    def run(self, target) -> list[RawFinding]:
        host = target.value
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.TIMEOUT_SECONDS
        resolver.lifetime = self.TIMEOUT_SECONDS

        findings = []
        any_record_type_succeeded = False
        ips: list[str] = []
        cnames: list[str] = []

        for record_type in RECORD_TYPES:
            try:
                answers = resolver.resolve(host, record_type)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # Legitimate outcome, not an error -- this host simply
                # has no records of this type.
                any_record_type_succeeded = True
                continue
            except dns.exception.DNSException:
                # Timeout, SERVFAIL, etc. on THIS record type only --
                # skip it, don't abort the whole scan over one flaky
                # query (e.g. a large TXT record needing TCP fallback).
                continue

            any_record_type_succeeded = True
            if record_type in ("A", "AAAA"):
                ips += [answer.to_text() for answer in answers]
                # The names followed on the way to the address, e.g.
                # shop.example.com -> shops.myshopify.com.
                response = getattr(answers, "response", None)
                for rrset in response.answer if response is not None else []:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        for record in rrset:
                            name = record.target.to_text().rstrip(".")
                            if name not in cnames:
                                cnames.append(name)
            for answer in answers:
                value = answer.to_text()
                findings.append(
                    RawFinding(
                        finding_type=Finding.FindingType.DNS_CHANGE,
                        identifier=f"{record_type}:{value}",
                        severity=Finding.Severity.INFO,
                        title=f"{record_type} record: {value}",
                        description=f"{host} has a {record_type} record: {value}",
                        raw_data={"record_type": record_type, "value": value},
                    )
                )

        if not any_record_type_succeeded:
            # Every single record type errored -- this points to a real
            # resolution problem (bad resolver config, network issue),
            # not "this host just has no MX record". Worth retrying.
            raise RuntimeError(f"DNS resolution failed for {host} on every record type")

        self._hosting = {
            "ips": ips,
            "cnames": cnames,
            "reverse_names": self._reverse_names(resolver, ips[: self.REVERSE_LOOKUPS]),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        return findings

    REVERSE_LOOKUPS = 2

    @staticmethod
    def _reverse_names(resolver, ips: list[str]) -> list[str]:
        names = []
        for ip in ips:
            try:
                answers = resolver.resolve(dns.reversename.from_address(ip), "PTR")
            except (dns.exception.DNSException, ValueError):
                continue
            names += [answer.to_text().rstrip(".") for answer in answers]
        return names

    def extract_asset_facts(self, target) -> dict:
        hosting = getattr(self, "_hosting", None)
        return {"hosting": hosting} if hosting else {}
