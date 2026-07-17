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

import dns.exception
import dns.resolver

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]


@register_scanner
class DnsMonitorScanner(BaseScanner):
    name = "dns_monitor"
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.DNS_CHANGE]

    TIMEOUT_SECONDS = 5

    def run(self, target) -> list[RawFinding]:
        host = target.value
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.TIMEOUT_SECONDS
        resolver.lifetime = self.TIMEOUT_SECONDS

        findings = []
        any_record_type_succeeded = False

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

        return findings