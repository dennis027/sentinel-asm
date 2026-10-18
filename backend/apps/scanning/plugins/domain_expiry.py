"""
The domain's own registration: when it expires, and whether it is
locked against transfer.

An expired domain takes the website and email down with it, and once
it is released anyone can register it and receive the organization's
email. A domain without the registrar's transfer lock is easier to
hijack through a compromised registrar account or a social-engineered
transfer.

Uses RDAP, the registries' public replacement for WHOIS, through IANA's
list of which server answers for each domain ending (no account
needed). Some country endings don't run RDAP yet; those are skipped.
"""

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from django.core.cache import cache

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

S = Finding.Severity
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_CACHE_KEY = "rdap:bootstrap"
TRANSFER_LOCKS = {"client transfer prohibited", "server transfer prohibited"}


def expiry_severity(days: int) -> str | None:
    if days <= 7:
        return S.CRITICAL
    if days <= 30:
        return S.HIGH
    if days <= 45:
        return S.MEDIUM
    return None


def server_for(domain: str, bootstrap: dict) -> str | None:
    labels = domain.lower().rstrip(".").split(".")
    # The longest matching ending wins ("co.uk" before "uk").
    for i in range(1, len(labels)):
        ending = ".".join(labels[i:])
        for endings, urls in bootstrap.get("services", []):
            if ending in endings and urls:
                return urls[0] if urls[0].endswith("/") else urls[0] + "/"
    return None


def parse(domain: str, data: dict, now: datetime) -> list[RawFinding]:
    findings = []
    expires = None
    for event in data.get("events", []):
        if event.get("eventAction") == "expiration":
            try:
                expires = datetime.fromisoformat(str(event.get("eventDate")).replace("Z", "+00:00"))
            except ValueError:
                pass
    registrar = ""
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = str(item[3])
    if expires:
        days = (expires - now).days
        severity = expiry_severity(days)
        if severity:
            title = (f"{domain} expired {-days} day(s) ago" if days < 0
                     else f"{domain} expires in {days} day(s)")
            findings.append(RawFinding(
                finding_type=Finding.FindingType.DOMAIN_REGISTRATION, identifier="expiry", severity=severity,
                title=title,
                description=(
                    f"The registration of {domain} {'ended' if days < 0 else 'ends'} on {expires.date().isoformat()}"
                    f"{f' (registrar: {registrar})' if registrar else ''}. When it lapses the website and email "
                    "stop working, and after a grace period anyone can register it."
                ),
                raw_data={"check": "domain_expiring", "expires": expires.isoformat(), "days_remaining": days,
                          "registrar": registrar},
                asset_value=domain,
            ))
    statuses = {str(status).lower() for status in data.get("status", [])}
    if statuses and not statuses & TRANSFER_LOCKS:
        findings.append(RawFinding(
            finding_type=Finding.FindingType.DOMAIN_REGISTRATION, identifier="transfer_lock", severity=S.LOW,
            title=f"{domain} is not locked against transfer",
            description=(
                f"The registry shows no transfer lock on {domain} (status: {', '.join(sorted(statuses))}). "
                "Anyone who gets into the registrar account, or talks the registrar round, can move the domain away."
            ),
            raw_data={"check": "transfer_lock_off", "status": sorted(statuses), "registrar": registrar},
            asset_value=domain,
        ))
    return findings


@register_scanner
class DomainExpiryScanner(BaseScanner):
    name = "domain_expiry"
    category = "email_domain"
    label = "Domain registration"
    description = "Warns before your domain's registration expires, and when it isn't locked against transfer."
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.DOMAIN_REGISTRATION]

    TIMEOUT = 15

    def run(self, target) -> list[RawFinding]:
        domain = target.root_domain
        server = server_for(domain, self._bootstrap())
        if not server:
            return []  # this ending has no RDAP service
        try:
            data = self._get(f"{server}domain/{domain}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []
            raise RuntimeError(f"RDAP lookup for {domain} failed: HTTP {exc.code}") from exc
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"RDAP lookup for {domain} failed: {exc}") from exc
        return parse(domain, data, datetime.now(timezone.utc))

    def _bootstrap(self) -> dict:
        bootstrap = cache.get(BOOTSTRAP_CACHE_KEY)
        if bootstrap is None:
            try:
                bootstrap = self._get(BOOTSTRAP_URL)
            except (OSError, ValueError) as exc:
                raise RuntimeError(f"Could not load the RDAP server list: {exc}") from exc
            cache.set(BOOTSTRAP_CACHE_KEY, bootstrap, 60 * 60 * 24)
        return bootstrap

    def _get(self, url: str) -> dict:
        request = urllib.request.Request(url, headers={"User-Agent": "densight/1.0",
                                                      "Accept": "application/rdap+json, application/json"})
        with urllib.request.urlopen(request, timeout=self.TIMEOUT) as response:
            return json.loads(response.read(2_000_000))
