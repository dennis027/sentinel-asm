"""
Finds subdomains that still point at something that is no longer there.

A subdomain is usually handed to a hosting or SaaS provider with a
CNAME record (shop.example.com -> example.myshopify.com). If the
account behind it is later closed but the CNAME is left in DNS, the
name is "dangling": whoever registers that account name at the
provider next gets to publish content on your subdomain.

Detection only. The scanner reads the CNAME, checks whether its target
still exists, and for providers known to hand out names this way,
looks for the provider's own "nothing is hosted here" page. It never
tries to claim anything.
"""

import dns.exception
import dns.resolver

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

# (CNAME suffix, provider, text the provider shows for an unclaimed
# name -- or None when the tell is simply that the target no longer
# resolves). Kept short and conservative: only providers where an
# unclaimed name has publicly been shown to be claimable by anyone.
PROVIDERS = [
    (".github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    (".herokuapp.com", "Heroku", "No such app"),
    (".herokudns.com", "Heroku", "No such app"),
    (".s3.amazonaws.com", "Amazon S3", "NoSuchBucket"),
    (".myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    (".surge.sh", "Surge", "project not found"),
    (".bitbucket.io", "Bitbucket", "Repository not found"),
    (".ghost.io", "Ghost", "The thing you were looking for is no longer here"),
    (".pantheonsite.io", "Pantheon", "The gods are wise"),
    (".readme.io", "ReadMe", "Project doesnt exist"),
    (".zendesk.com", "Zendesk", "Help Center Closed"),
    (".azurewebsites.net", "Azure App Service", None),
    (".cloudapp.net", "Azure Cloud Services", None),
    (".cloudapp.azure.com", "Azure Virtual Machines", None),
    (".trafficmanager.net", "Azure Traffic Manager", None),
    (".blob.core.windows.net", "Azure Blob Storage", None),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk", None),
]


def provider_for(cname_target: str) -> tuple[str, str | None] | None:
    target = cname_target.lower().rstrip(".")
    for suffix, provider, fingerprint in PROVIDERS:
        if target.endswith(suffix):
            return provider, fingerprint
    return None


def assess(host: str, cname_target: str | None, target_resolves: bool, body: str = "") -> RawFinding | None:
    """
    Decides what, if anything, to report. Pure function: the DNS and
    HTTP lookups are done by the caller and passed in.
    """
    if not cname_target:
        return None

    target = cname_target.lower().rstrip(".")
    provider = provider_for(target)
    raw = {"cname": target}

    if provider:
        name, fingerprint = provider
        unclaimed = (fingerprint is not None and fingerprint.lower() in body.lower()) or not target_resolves
        if unclaimed:
            return RawFinding(
                finding_type=Finding.FindingType.SUBDOMAIN_TAKEOVER,
                identifier=f"takeover:{target}",
                severity=Finding.Severity.HIGH,
                title=f"Subdomain points at an unclaimed {name} address",
                description=(
                    f"{host} is a CNAME to {target}, but nothing is hosted there any more. "
                    f"Anyone who registers that name with {name} could serve content on {host}."
                ),
                raw_data={**raw, "check": "takeover", "provider": name},
            )
        return None

    if not target_resolves:
        return RawFinding(
            finding_type=Finding.FindingType.SUBDOMAIN_TAKEOVER,
            identifier=f"dangling:{target}",
            severity=Finding.Severity.MEDIUM,
            title="Subdomain points at a name that no longer exists",
            description=(
                f"{host} is a CNAME to {target}, which does not resolve. The record is left over "
                "from something that has been removed."
            ),
            raw_data={**raw, "check": "dangling_cname"},
        )
    return None


@register_scanner
class SubdomainTakeoverScanner(BaseScanner):
    name = "subdomain_takeover"
    category = "email_domain"
    label = "Subdomain takeover"
    description = (
        "Finds subdomains still pointing at a cloud or hosting service you no longer use, "
        "which someone else could claim."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.SUBDOMAIN_TAKEOVER]

    TIMEOUT_SECONDS = 5

    def run(self, target) -> list[RawFinding]:
        host = target.value
        cname = self._cname(host)
        if cname is None:
            return []

        resolves = self._resolves(cname)
        body = ""
        provider = provider_for(cname)
        if provider and provider[1] and resolves:
            try:
                body = fetch(host).body
            except RuntimeError:
                body = ""  # unreachable is not evidence either way

        finding = assess(host, cname, resolves, body)
        return [finding] if finding else []

    def _resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = self.TIMEOUT_SECONDS
        return resolver

    def _cname(self, host: str) -> str | None:
        try:
            answers = self._resolver().resolve(host, "CNAME")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return None
        except dns.exception.DNSException as exc:
            raise RuntimeError(f"DNS lookup for {host} failed: {exc}") from exc
        return answers[0].target.to_text().rstrip(".")

    def _resolves(self, name: str) -> bool:
        for record_type in ("A", "AAAA"):
            try:
                self._resolver().resolve(name, record_type)
                return True
            except dns.resolver.NXDOMAIN:
                return False
            except dns.resolver.NoAnswer:
                continue
            except dns.exception.DNSException:
                # Couldn't find out. Treat as "exists": a timeout must
                # never be reported as a takeover risk.
                return True
        return False
