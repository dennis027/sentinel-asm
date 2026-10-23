"""
The search box language on the Assets page. Words are ANDed together;
a word without a prefix searches the host name.

    tech:nginx          runs software whose name contains "nginx"
    tag:payments        carries the label
    owner:amina         owned by someone matching (owner:me, owner:none)
    provider:aws        hosted on (provider:none = not identified)
    status:200          last web response (2xx, 3xx, 4xx, 5xx, none)
    port:22             has that port open
    severity:critical   has an open issue that severe (or worse with +: high+)
    importance:high     criticality (crown-jewel, high, normal, low)
    type:subdomain      asset type
    new:7               first seen in the last 7 days
    -word / -tag:x      excludes what follows

Unknown prefixes are searched as plain text, so typing "a:b" never errors.
"""

import shlex
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from apps.findings.models import Finding

from .models import Technology

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
STATUS_RANGES = {"2xx": (200, 299), "3xx": (300, 399), "4xx": (400, 499), "5xx": (500, 599)}


def _open_issues(**filters) -> Q:
    ids = Finding.objects.filter(is_active=True, status=Finding.Status.OPEN, **filters).values("asset_id")
    return Q(id__in=ids)


def term_q(key: str, value: str, user) -> Q | None:
    value = value.strip()
    lower = value.lower()
    if not value:
        return None
    if key == "tech":
        return Q(id__in=Technology.objects.filter(name__icontains=value).values("asset_id"))
    if key == "tag":
        return Q(tags__contains=[lower])
    if key == "owner":
        if lower == "none":
            return Q(owner__isnull=True)
        if lower == "me":
            return Q(owner=user)
        return (
            Q(owner__username__icontains=value) | Q(owner__first_name__icontains=value)
            | Q(owner__last_name__icontains=value) | Q(owner__email__icontains=value)
        )
    if key == "provider":
        if lower == "none":
            return Q(hosting__provider__isnull=True)
        return Q(hosting__provider__icontains=value)
    if key == "status":
        if lower == "none":
            return Q(web__status__isnull=True)
        if lower in STATUS_RANGES:
            low, high = STATUS_RANGES[lower]
            return Q(web__status__gte=low, web__status__lte=high)
        if lower.isdigit():
            return Q(web__status=int(lower))
        return None
    if key == "port":
        return _open_issues(finding_type=Finding.FindingType.OPEN_PORT, raw_data__port=value)
    if key == "severity":
        at_least = lower.endswith("+")
        lower = lower.rstrip("+")
        if lower not in SEVERITY_ORDER:
            return None
        levels = SEVERITY_ORDER[SEVERITY_ORDER.index(lower):] if at_least else [lower]
        return _open_issues(severity__in=levels)
    if key == "importance":
        return Q(criticality=lower.replace("-", "_"))
    if key == "type":
        return Q(asset_type=lower)
    if key == "new":
        if not lower.isdigit():
            return None
        return Q(first_seen__gte=timezone.now() - timedelta(days=int(lower)))
    return None


def apply_query(queryset, text: str, user):
    try:
        words = shlex.split(text or "")
    except ValueError:  # an unclosed quote
        words = (text or "").split()
    for word in words:
        negate = word.startswith("-") and len(word) > 1
        if negate:
            word = word[1:]
        key, _, value = word.partition(":")
        q = term_q(key.lower(), value, user) if value else None
        if q is None:
            q = Q(value__icontains=word)
        queryset = queryset.exclude(q) if negate else queryset.filter(q)
    return queryset.distinct()
