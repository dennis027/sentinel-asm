from .models import Asset


def ensure_root_domain_asset(organization) -> Asset:
    """
    The organization's root domain is itself a scan target, not just
    the seed for subdomain discovery. Subfinder only ever returns
    subdomains, so without this row the apex domain would never get a
    port scan, header audit or certificate check.
    """
    asset, _ = Asset.objects.get_or_create(
        organization=organization,
        value=organization.root_domain,
        defaults={"asset_type": Asset.AssetType.DOMAIN},
    )
    return asset
