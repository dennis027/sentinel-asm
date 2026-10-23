"""
Emerging threats: vulnerabilities CISA recently confirmed attackers are
exploiting (the KEV catalogue) in software this organization runs.

Matched on the software's name only -- scans rarely see exact versions
-- so each match is "may affect you; check your version", unless a
finding on the host already names the CVE, which makes it confirmed.
This is the "a Log4j-style event lands; are we exposed?" view.
"""

from datetime import timedelta

from django.utils import timezone

from apps.assets.models import Technology

from .models import Finding, KnownExploitedVulnerability

# Server-header spellings -> the name the catalogue uses.
ALIASES = {
    "microsoft-iis": "iis",
    "microsoft-httpapi": "windows",
    "apache httpd": "apache",
    "apache-coyote": "tomcat",
}
# Catalogue products under a vendor that mean "the product itself".
VENDOR_PRODUCTS = {"core", "http server", "multiple products"}


def _normalise(name: str) -> str:
    name = " ".join(name.lower().replace("_", " ").split())
    return ALIASES.get(name, name)


def matches(tech_name: str, vendor: str, product: str) -> bool:
    name = _normalise(tech_name)
    if len(name) < 3:
        return False
    vendor, product = vendor.lower(), product.lower()
    return (
        product == name
        or product.startswith(name + " ")
        or f"({name})" in product
        or (vendor == name and (product == vendor or product in VENDOR_PRODUCTS))
    )


def build_emerging_threats(organization, days: int = 90) -> dict:
    since = timezone.localdate() - timedelta(days=days)
    recent = list(KnownExploitedVulnerability.objects.filter(date_added__gte=since).order_by("-date_added"))

    software: dict[str, list] = {}
    for tech in Technology.objects.filter(asset__organization=organization, asset__is_active=True).select_related("asset"):
        software.setdefault(tech.name, []).append(tech)

    # (host, CVE) pairs a scan has already confirmed with a finding.
    confirmed_pairs = {
        (asset_id, cve)
        for asset_id, cves in Finding.objects.filter(
            asset__organization=organization, is_active=True, cves__overlap=[kev.cve_id for kev in recent],
        ).values_list("asset_id", "cves")
        for cve in cves
    } if recent else set()

    items = []
    for kev in recent:
        for name, techs in software.items():
            if not matches(name, kev.vendor, kev.product):
                continue
            hosts = {}
            for tech in techs:
                hosts.setdefault(tech.asset_id, {
                    "id": tech.asset_id, "value": tech.asset.value, "version": tech.version,
                    "confirmed": (tech.asset_id, kev.cve_id) in confirmed_pairs,
                })
            items.append({
                "cve": kev.cve_id,
                "name": kev.name,
                "vendor": kev.vendor,
                "product": kev.product,
                "description": kev.description,
                "required_action": kev.required_action,
                "date_added": kev.date_added,
                "due_date": kev.due_date,
                "ransomware": kev.ransomware,
                "software": name,
                "hosts": sorted(hosts.values(), key=lambda host: host["value"]),
                "confirmed": any(host["confirmed"] for host in hosts.values()),
            })
    items.sort(key=lambda item: (not item["confirmed"], not item["ransomware"], -item["date_added"].toordinal()))
    return {
        "days": days,
        "catalogue_recent": len(recent),
        "software_checked": len(software),
        "items": items,
    }
