"""
Organization-wide views over assets that don't belong to one page's
query: where the hosts are hosted, and the getting-started checklist.
"""

from collections import Counter

from django.conf import settings

from .models import Asset

SAMPLE_HOSTS = 6


def build_hosting(organization) -> dict:
    """Hosts grouped by who hosts them, and addresses shared by several hosts."""
    providers: dict[str, list[str]] = {}
    unknown, unchecked = [], 0
    addresses: Counter = Counter()
    hosts_by_address: dict[str, list[str]] = {}
    for value, hosting in organization.assets.filter(is_active=True).order_by("value").values_list("value", "hosting"):
        hosting = hosting or {}
        if not hosting.get("checked_at"):
            unchecked += 1
            continue
        for address in hosting.get("ips", []):
            addresses[address] += 1
            hosts_by_address.setdefault(address, []).append(value)
        if provider := hosting.get("provider"):
            providers.setdefault(provider, []).append(value)
        else:
            unknown.append(value)
    return {
        "providers": sorted(
            (
                {"provider": provider, "count": len(hosts), "hosts": hosts[:SAMPLE_HOSTS]}
                for provider, hosts in providers.items()
            ),
            key=lambda row: -row["count"],
        ),
        "unknown": {"count": len(unknown), "hosts": unknown[:SAMPLE_HOSTS]},
        "unchecked": unchecked,
        "addresses": len(addresses),
        # One address behind many names: a shared server or a load balancer worth knowing about.
        "shared_addresses": [
            {"address": address, "count": count, "hosts": hosts_by_address[address][:SAMPLE_HOSTS]}
            for address, count in addresses.most_common(10)
            if count > 1
        ],
    }


def build_getting_started(organization, user) -> dict:
    """The steps that make the platform useful, and which are done."""
    from apps.api.models import TwoFactorDevice
    from apps.notifications.models import NotificationRule
    from apps.scanning.models import ScanJob

    jobs = ScanJob.objects.filter(organization=organization, status=ScanJob.Status.SUCCESS)
    steps = [
        {
            "key": "verify",
            "title": "Prove you own the domain",
            "detail": f"Add a DNS record to {organization.root_domain} so scans are allowed.",
            "done": organization.is_domain_verified or not settings.REQUIRE_DOMAIN_VERIFICATION,
            "link": "/organization",
        },
        {
            "key": "discover",
            "title": "Find your hosts",
            "detail": "Run subdomain discovery or certificate transparency to fill in the inventory.",
            "done": jobs.filter(scanner_name__in=["subfinder", "cert_transparency"]).exists(),
            "link": "/scanners",
        },
        {
            "key": "scan",
            "title": "Run a full scan",
            "detail": "Check every host for open ports, weak encryption and known issues.",
            "done": jobs.filter(asset__isnull=False).exists(),
            "link": "/scanners",
        },
        {
            "key": "importance",
            "title": "Mark what matters most",
            "detail": "Flag crown jewels so their issues are fixed first.",
            "done": organization.assets.filter(criticality__in=[Asset.Criticality.CROWN_JEWEL, Asset.Criticality.HIGH]).exists(),
            "link": "/assets",
        },
        {
            "key": "owners",
            "title": "Give hosts an owner",
            "detail": "New issues on a host go straight to the person who runs it.",
            "done": organization.assets.filter(owner__isnull=False).exists(),
            "link": "/assets",
        },
        {
            "key": "team",
            "title": "Invite your team",
            "detail": "Bring in the people who will fix what scans find.",
            "done": organization.memberships.count() > 1 or organization.invitations.filter(accepted_at__isnull=True, revoked_at__isnull=True).exists(),
            "link": "/organization",
        },
        {
            "key": "alerts",
            "title": "Turn on alerts",
            "detail": "Get an email, Slack or webhook message when something serious appears.",
            "done": NotificationRule.objects.filter(organization=organization).exists(),
            "link": "/notification-rules",
        },
        {
            "key": "two_factor",
            "title": "Protect your account",
            "detail": "Turn on two-step sign-in with an authenticator app.",
            "done": TwoFactorDevice.objects.filter(user=user, confirmed_at__isnull=False).exists(),
            "link": "/account-settings",
        },
    ]
    done = sum(step["done"] for step in steps)
    return {"steps": steps, "done": done, "total": len(steps), "complete": done == len(steps)}
