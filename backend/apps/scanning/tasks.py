"""
Generic scan-execution task. This function is scanner-agnostic: it
looks up the right plugin by name, runs it, and reconciles the results
into Finding rows. Adding a new scanner never touches this file.
"""

import logging
import time

from celery import shared_task
from django.utils import timezone

from apps.assets.models import Asset, Technology
from apps.findings.models import Finding
from apps.notifications.tasks import notify_new_findings
from apps.organizations.models import Organization

from .metrics import FINDINGS_CREATED_TOTAL, SCAN_JOB_DURATION_SECONDS, SCAN_JOBS_TOTAL
from .models import ScanJob
from .plugins.registry import get_scanner, list_scanners

logger = logging.getLogger("apps.scanning")


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def run_scan_job(self, scan_job_id: str):
    scan_job = ScanJob.objects.select_related("asset", "organization").get(id=scan_job_id)
    start_time = time.monotonic()

    scan_job.status = ScanJob.Status.RUNNING
    scan_job.started_at = timezone.now()
    scan_job.celery_task_id = self.request.id or ""
    scan_job.error_message = ""
    scan_job.save(update_fields=["status", "started_at", "celery_task_id", "error_message"])

    logger.info(
        "scan_job_started",
        extra={
            "scan_job_id": str(scan_job.id),
            "scanner_name": scan_job.scanner_name,
            "organization_id": str(scan_job.organization_id),
            "asset_id": str(scan_job.asset_id) if scan_job.asset_id else None,
        },
    )

    try:
        scanner_cls = get_scanner(scan_job.scanner_name)
        scanner = scanner_cls()

        target = scan_job.asset if scanner.applies_to == "asset" else scan_job.organization
        raw_findings = scanner.run(target)

        # (asset_id, dedupe_key) pairs actually produced this run -- used
        # below to resolve findings this scanner owns that stopped
        # appearing (e.g. a closed port, or for org-level scanners, kept
        # scoped to assets under this organization rather than one asset).
        seen: set[tuple] = set()
        newly_created_finding_ids: list[str] = []

        for rf in raw_findings:
            if scanner.applies_to == "asset":
                finding_asset = scan_job.asset
            else:
                if not rf.asset_value:
                    raise ValueError(
                        f"{scanner.name} is organization-level but returned a "
                        f"RawFinding without asset_value -- can't determine "
                        f"which asset '{rf.title}' belongs to."
                    )
                finding_asset, _ = Asset.objects.get_or_create(
                    organization=scan_job.organization,
                    value=rf.asset_value,
                    defaults={"asset_type": Asset.AssetType.SUBDOMAIN},
                )

            dedupe_key = Finding.build_dedupe_key(rf.finding_type, rf.identifier)
            finding, finding_created = Finding.objects.update_or_create(
                asset=finding_asset,
                dedupe_key=dedupe_key,
                defaults=dict(
                    scan_job=scan_job,
                    finding_type=rf.finding_type,
                    severity=rf.severity,
                    title=rf.title,
                    description=rf.description,
                    raw_data=rf.raw_data,
                    is_active=True,
                ),
            )
            if finding_created:
                newly_created_finding_ids.append(str(finding.id))
                FINDINGS_CREATED_TOTAL.labels(
                    finding_type=rf.finding_type, severity=rf.severity
                ).inc()
            seen.add((finding_asset.id, dedupe_key))

        # Anything this scanner owns that wasn't seen this run has been
        # resolved (e.g. a port that closed, a subdomain that stopped
        # resolving) -- flip it, don't delete it, so historical diffing
        # ("resolved today") stays queryable.
        if scanner.owned_finding_types:
            if scanner.applies_to == "asset":
                candidates = Finding.objects.filter(
                    asset=scan_job.asset,
                    finding_type__in=scanner.owned_finding_types,
                    is_active=True,
                )
            else:
                candidates = Finding.objects.filter(
                    asset__organization=scan_job.organization,
                    finding_type__in=scanner.owned_finding_types,
                    is_active=True,
                )
            for finding in candidates:
                if (finding.asset_id, finding.dedupe_key) not in seen:
                    finding.is_active = False
                    finding.save(update_fields=["is_active"])

        # Tech fingerprinting is a separate, optional side-channel from
        # findings -- only applies to asset-level scanners that override
        # extract_technologies() (currently just httpx).
        if scanner.applies_to == "asset":
            for raw_tech in scanner.extract_technologies(scan_job.asset):
                Technology.objects.update_or_create(
                    asset=scan_job.asset,
                    name=raw_tech.name,
                    version=raw_tech.version,
                    defaults={"category": raw_tech.category},
                )

        scan_job.status = ScanJob.Status.SUCCESS
        scan_job.finished_at = timezone.now()
        scan_job.save(update_fields=["status", "finished_at"])

        duration = time.monotonic() - start_time
        SCAN_JOB_DURATION_SECONDS.labels(scanner_name=scan_job.scanner_name).observe(duration)
        SCAN_JOBS_TOTAL.labels(scanner_name=scan_job.scanner_name, status="success").inc()

        logger.info(
            "scan_job_succeeded",
            extra={
                "scan_job_id": str(scan_job.id),
                "scanner_name": scan_job.scanner_name,
                "duration_seconds": round(duration, 3),
                "findings_created": len(newly_created_finding_ids),
            },
        )

        if newly_created_finding_ids:
            notify_new_findings.delay(str(scan_job.id), newly_created_finding_ids)

    except Exception as exc:
        # self.request.retries is 0 on the first attempt, incrementing on
        # each automatic retry. Only mark the job terminally FAILED once
        # retries are actually exhausted -- otherwise a manual re-trigger
        # during the 30s retry backoff window would race the automatic
        # retry that's already scheduled to run against this same job.
        if self.request.retries >= self.max_retries:
            scan_job.status = ScanJob.Status.FAILED
            scan_job.error_message = str(exc)
            scan_job.finished_at = timezone.now()
            scan_job.save(update_fields=["status", "error_message", "finished_at"])
            SCAN_JOBS_TOTAL.labels(scanner_name=scan_job.scanner_name, status="failed").inc()
            logger.error(
                "scan_job_failed",
                extra={
                    "scan_job_id": str(scan_job.id),
                    "scanner_name": scan_job.scanner_name,
                    "error": str(exc),
                    "retries_exhausted": True,
                },
            )
        else:
            scan_job.status = ScanJob.Status.RETRYING
            scan_job.error_message = str(exc)
            scan_job.save(update_fields=["status", "error_message"])
            logger.warning(
                "scan_job_retrying",
                extra={
                    "scan_job_id": str(scan_job.id),
                    "scanner_name": scan_job.scanner_name,
                    "error": str(exc),
                    "attempt": self.request.retries + 1,
                },
            )
        raise self.retry(exc=exc)


@shared_task
def trigger_daily_scans():
    """
    Called once a day by celery-beat (see the periodic task set up by
    `manage.py setup_periodic_tasks`). Fans out into one ScanJob per
    (active organization/asset x registered scanner) combination,
    scoped correctly by each scanner's applies_to.

    Deliberately scanner-agnostic: iterates the plugin registry rather
    than a hardcoded scanner list, so adding a new scanner plugin makes
    it part of daily monitoring automatically -- no change needed here.

    Idempotency (ScanJob.build_idempotency_key, same scanner + same
    target + same day) means this is safe to call more than once on
    the same day -- e.g. if beat double-fires -- without creating
    duplicate scans.
    """
    org_level_scanners = []
    asset_level_scanners = []
    for scanner_name in list_scanners():
        scanner_cls = get_scanner(scanner_name)
        if scanner_cls.applies_to == "organization":
            org_level_scanners.append(scanner_name)
        else:
            asset_level_scanners.append(scanner_name)

    queued = 0

    for org in Organization.objects.filter(is_active=True):
        for scanner_name in org_level_scanners:
            queued += _enqueue_if_new(
                scanner_name, target_value=org.root_domain,
                organization=org, asset=None,
            )

        for asset in org.assets.filter(is_active=True):
            for scanner_name in asset_level_scanners:
                queued += _enqueue_if_new(
                    scanner_name, target_value=asset.value,
                    organization=org, asset=asset,
                )

    logger.info("daily_scans_triggered", extra={"jobs_queued": queued})
    return f"Queued {queued} scan job(s) for today."


def _enqueue_if_new(scanner_name, target_value, organization, asset) -> int:
    idempotency_key = ScanJob.build_idempotency_key(scanner_name, target_value)
    scan_job, created = ScanJob.objects.get_or_create(
        idempotency_key=idempotency_key,
        defaults=dict(organization=organization, asset=asset, scanner_name=scanner_name),
    )
    if created:
        run_scan_job.delay(str(scan_job.id))
    return 1 if created else 0