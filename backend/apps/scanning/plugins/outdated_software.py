"""
Flags web server software that is past its end of life, going by the
versions servers announce in their Server and X-Powered-By headers.

Honest about its limits: many servers hide or fake these headers, and
Linux distributions backport fixes without changing the version
number. So this only reports versions old enough that the whole
release line is unsupported -- not "a newer patch release exists".

The table below is a snapshot and needs a look once or twice a year.
"""

import re

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

# product (lower case, as it appears in headers) ->
#   (display name, oldest release line still supported, note)
SUPPORTED_FROM = {
    "php": ("PHP", (8, 2), "PHP 8.1 and earlier no longer receive security fixes"),
    "apache": ("Apache HTTP Server", (2, 4), "Apache 2.2 and earlier reached end of life in 2017"),
    "nginx": ("nginx", (1, 20), "this nginx release line is several years out of support"),
    "microsoft-iis": ("Microsoft IIS", (10, 0), "it ships with a Windows Server version that is out of support"),
    "openssl": ("OpenSSL", (3, 0), "OpenSSL 1.1.1 and earlier reached end of life in 2023"),
    "asp.net": ("ASP.NET", (4, 0), "this .NET Framework version is out of support"),
}

_PRODUCT_VERSION = re.compile(r"([A-Za-z][A-Za-z.\-]*)/(\d+(?:\.\d+)*)")


def parse_products(*header_values: str | None) -> dict[str, str]:
    """'Apache/2.2.15 (CentOS) PHP/5.4.16' -> {'apache': '2.2.15', 'php': '5.4.16'}"""
    products: dict[str, str] = {}
    for value in header_values:
        for name, version in _PRODUCT_VERSION.findall(value or ""):
            products.setdefault(name.lower(), version)
    return products


def _as_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split(".")[:3])


def findings_for(host: str, products: dict[str, str]) -> list[RawFinding]:
    """Pure function: products seen -> findings."""
    results = []
    for product, version in sorted(products.items()):
        if product not in SUPPORTED_FROM:
            continue
        name, minimum, note = SUPPORTED_FROM[product]
        if _as_tuple(version)[: len(minimum)] >= minimum:
            continue
        results.append(RawFinding(
            finding_type=Finding.FindingType.OUTDATED_SOFTWARE,
            # Keyed by product, not version: an upgrade to another old
            # version updates this finding instead of adding a second.
            identifier=product,
            severity=Finding.Severity.MEDIUM,
            title=f"{name} {version} is out of support",
            description=f"{host} reports running {name} {version}; {note}.",
            raw_data={"check": "end_of_life", "product": name, "version": version},
        ))
    return results


@register_scanner
class OutdatedSoftwareScanner(BaseScanner):
    name = "outdated_software"
    category = "web"
    label = "Outdated software"
    description = (
        "Flags web servers and frameworks announcing a version that no longer gets security fixes."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.OUTDATED_SOFTWARE]

    def run(self, target) -> list[RawFinding]:
        host = target.value
        headers = fetch(host).headers
        products = parse_products(headers.get("Server"), headers.get("X-Powered-By"))
        if aspnet := headers.get("X-AspNet-Version"):
            products.setdefault("asp.net", aspnet)
        return findings_for(host, products)
