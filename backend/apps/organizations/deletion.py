"""
Deleting an organization and everything under it.

Not just `organization.delete()`: Django's cascade loads the rows it
is about to remove, which for an organization with hundreds of
thousands of scan jobs means minutes and a lot of memory. The big
tables are cleared with one DELETE statement each, children first,
and only then is the (now small) organization row itself removed.
"""

import logging

from django.core.cache import cache
from django.db import transaction

logger = logging.getLogger("apps.organizations")


def delete_organization(organization) -> dict[str, int]:
    """Returns how many rows of each kind were removed."""
    # Imported here: these apps import organizations.models at load time.
    from apps.assets.models import Asset, Technology
    from apps.audit_logs.models import ActivityEvent
    from apps.findings.models import Finding, FindingComment, RiskSnapshot
    from apps.logs.models import ErrorGroup, LogAlertRule, LogDetection, LogEvent, LogSource
    from apps.scanning import screenshot_store
    from apps.scanning.models import ScanJob
    from apps.scanning.plugins.registry import list_scanners
    from apps.scanning.tasks import domain_scan_lock_key

    organization_id = organization.id
    asset_ids = list(Asset.objects.filter(organization=organization).values_list("id", flat=True))

    with transaction.atomic():
        # Order matters: each statement removes rows nothing else
        # points at any more, so none of them needs a cascade.
        removed = {
            "log_events": LogEvent.objects.filter(organization=organization)._raw_delete(LogEvent.objects.db),
            "error_groups": ErrorGroup.objects.filter(organization=organization)._raw_delete(ErrorGroup.objects.db),
            "log_detections": LogDetection.objects.filter(organization=organization)._raw_delete(LogDetection.objects.db),
            "log_alert_rules": LogAlertRule.objects.filter(organization=organization)._raw_delete(
                LogAlertRule.objects.db
            ),
            "log_sources": LogSource.objects.filter(organization=organization)._raw_delete(LogSource.objects.db),
            "comments": FindingComment.objects.filter(finding__asset__organization=organization)._raw_delete(
                FindingComment.objects.db
            ),
            "activity": ActivityEvent.objects.filter(organization=organization)._raw_delete(ActivityEvent.objects.db),
            "snapshots": RiskSnapshot.objects.filter(organization=organization)._raw_delete(RiskSnapshot.objects.db),
            "findings": Finding.objects.filter(asset__organization=organization)._raw_delete(Finding.objects.db),
            "scan_jobs": ScanJob.objects.filter(organization=organization)._raw_delete(ScanJob.objects.db),
            "technologies": Technology.objects.filter(asset__organization=organization)._raw_delete(
                Technology.objects.db
            ),
            "assets": Asset.objects.filter(organization=organization)._raw_delete(Asset.objects.db),
        }
        # Memberships and notification rules are few; the ordinary
        # cascade handles them along with the organization row.
        organization.delete()

    # Only after the database commit: files can't be rolled back.
    for asset_id in asset_ids:
        screenshot_store.delete_for_asset(asset_id)

    for scanner_name in list_scanners():
        cache.delete(domain_scan_lock_key(organization_id, scanner_name))

    logger.info("organization_deleted", extra={"organization_id": str(organization_id), **removed})
    return removed
