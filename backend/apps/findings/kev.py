"""
CISA's Known Exploited Vulnerabilities (KEV) catalogue: CVEs attackers
are confirmed to be exploiting. Vulnerability management guidance
(CISA, and the tools built on it) puts these first: a KEV-listed CVE on
an internet-facing host is the most urgent thing there is.

    https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Synced daily by celery-beat; `manage.py sync_kev --file catalogue.json`
loads a downloaded copy for servers without internet access.
"""

import json
import logging
import urllib.request
from datetime import date

from django.core.cache import cache

from .models import KnownExploitedVulnerability

logger = logging.getLogger("apps.findings")

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
INDEX_CACHE_KEY = "kev:index"


def _date(value):
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def load(catalogue: dict) -> int:
    """Upserts the catalogue's entries; returns how many there are."""
    rows = []
    for item in catalogue.get("vulnerabilities", []):
        cve = str(item.get("cveID", "")).upper().strip()
        if not cve.startswith("CVE-"):
            continue
        rows.append(KnownExploitedVulnerability(
            cve_id=cve,
            vendor=str(item.get("vendorProject", ""))[:255],
            product=str(item.get("product", ""))[:255],
            name=str(item.get("vulnerabilityName", ""))[:500],
            description=str(item.get("shortDescription", "")),
            required_action=str(item.get("requiredAction", "")),
            date_added=_date(item.get("dateAdded")),
            due_date=_date(item.get("dueDate")),
            ransomware=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
        ))
    KnownExploitedVulnerability.objects.bulk_create(
        rows, batch_size=500, update_conflicts=True, unique_fields=["cve_id"],
        update_fields=["vendor", "product", "name", "description", "required_action", "date_added", "due_date",
                       "ransomware"],
    )
    cache.delete(INDEX_CACHE_KEY)
    return len(rows)


def sync(timeout: float = 60) -> int:
    request = urllib.request.Request(FEED_URL, headers={"User-Agent": "densight/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return load(json.loads(response.read()))


def index() -> dict[str, dict]:
    """CVE id -> what the UI shows about it; cached, it changes once a day at most."""
    cached = cache.get(INDEX_CACHE_KEY)
    if cached is None:
        cached = {
            row.cve_id: {
                "cve": row.cve_id,
                "name": row.name,
                "date_added": row.date_added.isoformat() if row.date_added else None,
                "due_date": row.due_date.isoformat() if row.due_date else None,
                "ransomware": row.ransomware,
                "required_action": row.required_action,
            }
            for row in KnownExploitedVulnerability.objects.all()
        }
        cache.set(INDEX_CACHE_KEY, cached, 3600)
    return cached


def known_exploited(cves) -> dict | None:
    """The KEV entry for the first of these CVEs that is in the catalogue."""
    if not cves:
        return None
    catalogue = index()
    for cve in cves:
        if cve in catalogue:
            return catalogue[cve]
    return None
