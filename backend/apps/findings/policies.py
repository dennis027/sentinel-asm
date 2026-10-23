"""
Checks an organization's hosts against its attack surface policies
(SurfacePolicy) and keeps one "Breaks a policy" finding per host and
policy in step: created when a host starts breaking it, resolved when it
stops (or the policy is turned off or deleted).

Runs after every scan of a host, and over the whole organization when a
policy is added or changed.
"""

from fnmatch import fnmatch

from django.utils import timezone

from apps.assets.models import Asset, Technology

from .models import Finding, SurfacePolicy

TYPE = Finding.FindingType.POLICY_VIOLATION


def dedupe_key(policy_id) -> str:
    return Finding.build_dedupe_key(TYPE, f"policy:{policy_id}")


def _breaches(policy: SurfacePolicy, assets) -> dict:
    """{asset_id: what about it breaks the policy}."""
    value = policy.value.strip()
    if policy.kind == SurfacePolicy.Kind.PORT:
        rows = Finding.objects.filter(
            asset__in=assets, finding_type=Finding.FindingType.OPEN_PORT, is_active=True, raw_data__port=value,
        ).values_list("asset_id", flat=True)
        return {asset_id: f"has port {value} open" for asset_id in rows}
    if policy.kind == SurfacePolicy.Kind.TECHNOLOGY:
        rows = Technology.objects.filter(asset__in=assets, name__icontains=value).values_list("asset_id", "name")
        return {asset_id: f"runs {name}" for asset_id, name in rows}
    if policy.kind == SurfacePolicy.Kind.HOSTNAME:
        pattern = value.lower()
        return {
            asset_id: "has a matching name"
            for asset_id, name in assets.values_list("id", "value")
            if fnmatch(name, pattern)
        }
    if policy.kind == SurfacePolicy.Kind.PROVIDER:
        rows = assets.filter(hosting__provider__iexact=value).values_list("id", "hosting__provider")
        return {asset_id: f"is hosted on {provider}" for asset_id, provider in rows}
    return {}


def evaluate(organization, asset_ids=None) -> list[str]:
    """
    Brings policy findings up to date for the organization (or just the
    given hosts). Returns the ids of findings created by this call.
    """
    assets = Asset.objects.filter(organization=organization, is_active=True)
    if asset_ids is not None:
        assets = assets.filter(id__in=asset_ids)

    wanted: dict[tuple, tuple[SurfacePolicy, str]] = {}
    for policy in SurfacePolicy.objects.filter(organization=organization, enabled=True):
        for asset_id, detail in _breaches(policy, assets).items():
            wanted[(asset_id, dedupe_key(policy.id))] = (policy, detail)

    values = dict(assets.values_list("id", "value"))
    created_ids = []
    for (asset_id, key), (policy, detail) in wanted.items():
        finding, created = Finding.objects.update_or_create(
            asset_id=asset_id,
            dedupe_key=key,
            defaults=dict(
                finding_type=TYPE,
                severity=policy.severity,
                title=f"Breaks policy: {policy.name}",
                description=f"{values[asset_id]} {detail}. The policy says {policy.rule}.",
                raw_data={"policy_id": str(policy.id), "rule": policy.rule, "guidance": policy.guidance},
                is_active=True,
                resolved_at=None,
            ),
        )
        if created:
            created_ids.append(str(finding.id))

    stale = [
        finding_id
        for finding_id, asset_id, key in Finding.objects.filter(
            asset__in=assets, finding_type=TYPE, is_active=True
        ).values_list("id", "asset_id", "dedupe_key")
        if (asset_id, key) not in wanted
    ]
    if stale:
        Finding.objects.filter(id__in=stale).update(is_active=False, resolved_at=timezone.now())
    return created_ids
