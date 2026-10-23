"""
The attack surface's change feed: what appeared and what went away,
host by host, newest first. Built from what scans already keep (assets'
first_seen, technologies' first_seen, findings' first_seen/resolved_at),
so there is no separate history to maintain.

Answers "what's different since last week?" in the terms an attacker
would care about: a new host, a newly open port, a new piece of
software, a host that disappeared, a new certificate.
"""

from datetime import timedelta

from django.utils import timezone

from apps.assets.models import Asset, Technology

from .models import Finding

KINDS = {
    "host_added": "New host",
    "host_gone": "Host stopped resolving",
    "port_opened": "Port opened",
    "port_closed": "Port closed",
    "software_seen": "New software",
    "certificate": "New certificate",
    "dns_changed": "DNS record changed",
}
LIMIT = 300


def build_surface_changes(organization, days: int = 30, kind: str | None = None) -> dict:
    since = timezone.now() - timedelta(days=days)
    findings = Finding.objects.filter(asset__organization=organization).select_related("asset")
    events = []

    def add(event_kind, at, asset, detail):
        events.append({
            "kind": event_kind,
            "label": KINDS[event_kind],
            "at": at,
            "asset": asset.id,
            "asset_value": asset.value,
            "detail": detail,
        })

    new_hosts = Asset.objects.filter(organization=organization, first_seen__gte=since)
    new_host_ids = set(new_hosts.values_list("id", flat=True))
    for asset in new_hosts:
        add("host_added", asset.first_seen, asset,
            "Added by hand" if asset.source == Asset.Source.MANUAL else "Found by discovery")

    for finding in findings.filter(finding_type=Finding.FindingType.OPEN_PORT, first_seen__gte=since):
        add("port_opened", finding.first_seen, finding.asset, _port(finding))
    for finding in findings.filter(finding_type=Finding.FindingType.OPEN_PORT, resolved_at__gte=since):
        add("port_closed", finding.resolved_at, finding.asset, _port(finding))

    for tech in Technology.objects.filter(asset__organization=organization, first_seen__gte=since).select_related("asset"):
        add("software_seen", tech.first_seen, tech.asset, f"{tech.name} {tech.version}".strip())

    for finding in findings.filter(finding_type=Finding.FindingType.CERT_ISSUED, first_seen__gte=since):
        add("certificate", finding.first_seen, finding.asset, finding.title)

    # A record that appeared on a host that isn't new is a change worth seeing
    # (it moved, or a new mail or name server); on a new host it's just setup.
    address_records = {"A", "AAAA"}
    for finding in findings.filter(finding_type=Finding.FindingType.DNS_CHANGE, first_seen__gte=since).exclude(
        asset_id__in=new_host_ids
    ):
        add("dns_changed", finding.first_seen, finding.asset, finding.title)

    # Hosts whose address records all went away in the window: the name no longer resolves.
    still_resolving = set(
        findings.filter(
            finding_type=Finding.FindingType.DNS_CHANGE, is_active=True, raw_data__record_type__in=address_records,
        ).values_list("asset_id", flat=True)
    )
    gone: dict = {}
    for finding in findings.filter(
        finding_type=Finding.FindingType.DNS_CHANGE, resolved_at__gte=since, raw_data__record_type__in=address_records,
    ).exclude(asset_id__in=still_resolving):
        if finding.asset_id not in gone or finding.resolved_at > gone[finding.asset_id].resolved_at:
            gone[finding.asset_id] = finding
    for finding in gone.values():
        add("host_gone", finding.resolved_at, finding.asset, "Its address records were removed")

    counts = {event_kind: 0 for event_kind in KINDS}
    for event in events:
        counts[event["kind"]] += 1
    if kind in KINDS:
        events = [event for event in events if event["kind"] == kind]
    events.sort(key=lambda event: event["at"], reverse=True)
    return {
        "days": days,
        "since": since,
        "counts": counts,
        "kinds": KINDS,
        "total": len(events),
        "events": events[:LIMIT],
    }


def _port(finding) -> str:
    raw = finding.raw_data or {}
    port = f"{raw.get('port', '?')}/{raw.get('protocol', 'tcp')}"
    service = raw.get("service")
    return f"{port} ({service})" if service else port
