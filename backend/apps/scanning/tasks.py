"""
Generic scan-execution task. This function is scanner-agnostic: it
looks up the right plugin by name, runs it, and reconciles the results
into Finding rows. Adding a new scanner never touches this file.
"""

import logging
import time
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.core.cache import cache
from django.db.models import F, Q
from django.utils import timezone

from apps.assets.models import Asset, Technology
from apps.audit_logs.activity import record as record_activity
from apps.audit_logs.models import ActivityEvent
from apps.findings.models import Finding
from apps.notifications.tasks import notify_new_findings
from apps.organizations.models import Organization

from .metrics import FINDINGS_CREATED_TOTAL, SCAN_JOB_DURATION_SECONDS, SCAN_JOBS_TOTAL
from .models import ScanJob
from .plugins.registry import get_scanner, list_scanners
from .targets import TargetNotAllowed, assert_public_target

logger = logging.getLogger("apps.scanning")


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def run_scan_job(self, scan_job_id: str):
    try:
        scan_job = ScanJob.objects.select_related("asset", "organization").get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        # Its organization (or the job) was deleted while this sat in
        # the queue. Nothing to scan, nothing to record, nothing to retry.
        logger.info("scan_job_gone", extra={"scan_job_id": scan_job_id})
        return
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
        if scanner.applies_to == "asset":
            # The organization has said this host must not be tested
            # (someone else runs it). Checked here as well as when jobs
            # are queued, for jobs queued before the exclusion was added.
            if scan_job.organization.is_out_of_scope(scan_job.asset.value):
                raise TargetNotAllowed(
                    f"{scan_job.asset.value} is out of scope for {scan_job.organization.name}; it is not scanned."
                )
            # Org-level scanners (subfinder) are passive lookups that
            # never connect to the target; asset-level ones do.
            assert_public_target(scan_job.asset.value)
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
            previous = (
                Finding.objects.filter(asset=finding_asset, dedupe_key=dedupe_key)
                .values("is_active", "resolved_at")
                .first()
            )
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
                    cves=Finding.extract_cves(rf.title, rf.raw_data),
                    is_active=True,
                    resolved_at=None,
                ),
            )
            came_back = (
                previous is not None
                and not previous["is_active"]
                and previous["resolved_at"] is not None
                and rf.finding_type not in Finding.INVENTORY_TYPES
            )
            if came_back:
                # It had been fixed and now it's back: the fix didn't stick.
                Finding.objects.filter(id=finding.id).update(
                    reopened_count=F("reopened_count") + 1, reopened_at=timezone.now()
                )
                record_activity(
                    None, scan_job.organization, ActivityEvent.Verb.FINDING_REOPENED,
                    f"'{rf.title}' on {finding_asset.value} came back after being fixed",
                    finding=finding,
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
            resolved_ids = [
                finding_id
                for finding_id, asset_id, dedupe_key in candidates.values_list(
                    "id", "asset_id", "dedupe_key"
                )
                if (asset_id, dedupe_key) not in seen
            ]
            if resolved_ids:
                Finding.objects.filter(id__in=resolved_ids).update(
                    is_active=False, resolved_at=timezone.now()
                )

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

    except TargetNotAllowed as exc:
        # A policy refusal, not a transient failure -- retrying can't
        # change the answer, so fail the job immediately.
        scan_job.status = ScanJob.Status.FAILED
        scan_job.error_message = str(exc)
        scan_job.finished_at = timezone.now()
        scan_job.save(update_fields=["status", "error_message", "finished_at"])
        SCAN_JOBS_TOTAL.labels(scanner_name=scan_job.scanner_name, status="failed").inc()
        logger.warning(
            "scan_job_target_refused",
            extra={
                "scan_job_id": str(scan_job.id),
                "scanner_name": scan_job.scanner_name,
                "error": str(exc),
            },
        )

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
        if not org.scans_allowed:
            # Domain not verified yet -- same rule the manual trigger
            # endpoint enforces.
            continue

        for scanner_name in org_level_scanners:
            queued += _enqueue_if_new(
                scanner_name, target_value=org.root_domain,
                organization=org, asset=None,
            )

        for asset in org.scannable_assets():
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
        defaults=dict(organization=organization, asset=asset, scanner_name=scanner_name,
                      trigger=ScanJob.Trigger.SCHEDULE, run_id=ScanJob.schedule_run_id(organization.id)),
    )
    if created:
        run_scan_job.delay(str(scan_job.id))
    return 1 if created else 0


@shared_task
def reap_stale_scan_jobs():
    """
    Called every few minutes by celery-beat. A worker that's killed
    mid-scan (OOM, deploy, host reboot) never gets to write a final
    status, so its job would sit in RUNNING forever -- and since a
    same-day retrigger only re-enqueues FAILED jobs, that target
    couldn't be scanned again until tomorrow. Anything that's been
    unfinished for longer than any scan can legitimately take (see
    CELERY_TASK_TIME_LIMIT) is marked FAILED here.
    """
    now = timezone.now()
    running_cutoff = now - timedelta(minutes=settings.SCAN_JOB_STALE_AFTER_MINUTES)
    # PENDING jobs are still waiting in the queue, which is normal for a
    # long time after the daily fan-out -- only give up on one that has
    # sat there for a whole day (the broker lost it).
    pending_cutoff = now - timedelta(days=1)

    stale = ScanJob.objects.filter(
        Q(
            status__in=[ScanJob.Status.RUNNING, ScanJob.Status.RETRYING],
            started_at__lt=running_cutoff,
        )
        | Q(status=ScanJob.Status.PENDING, created_at__lt=pending_cutoff)
    )
    reaped = stale.update(
        status=ScanJob.Status.FAILED,
        error_message="Scan did not finish (worker stopped or timed out). Re-run to try again.",
        finished_at=now,
    )

    if reaped:
        logger.warning("stale_scan_jobs_reaped", extra={"count": reaped})
    return f"Marked {reaped} stale scan job(s) as failed."


FAN_OUT_CHUNK = 1000


def domain_scan_lock_key(organization_id, scanner_name: str) -> str:
    return f"domain-scan:{organization_id}:{scanner_name}"


@shared_task
def fan_out_domain_scan(organization_id: str, scanner_name: str, batch_id: str, user_id: int | None = None):
    """
    Starts one asset-level scanner on EVERY active asset of an
    organization -- what "Run scan" on the Scanners page does. Runs as
    a task rather than in the request because a large organization
    means tens of thousands of rows and queue messages.

    Jobs are created in chunks and each chunk is enqueued as soon as it
    exists, so scanning starts immediately instead of after the last
    row is written. The batch id doubles as the idempotency nonce: a
    deliberate run always gets fresh jobs, even for assets the daily
    schedule already covered today.
    """
    organization = Organization.objects.get(id=organization_id)
    queued = 0
    try:
        chunk: list[ScanJob] = []
        assets = organization.scannable_assets().only("id", "value")
        for asset in assets.iterator(chunk_size=FAN_OUT_CHUNK):
            chunk.append(
                ScanJob(
                    organization=organization,
                    asset=asset,
                    scanner_name=scanner_name,
                    batch_id=batch_id,
                    trigger=ScanJob.Trigger.DOMAIN,
                    run_id=batch_id,
                    triggered_by_id=user_id,
                    idempotency_key=ScanJob.build_idempotency_key(
                        scanner_name, asset.value, nonce=batch_id
                    ),
                )
            )
            if len(chunk) >= FAN_OUT_CHUNK:
                queued += _create_and_enqueue(chunk)
                chunk = []
        queued += _create_and_enqueue(chunk)
    finally:
        # From here the unfinished jobs themselves are what stops a
        # second run from starting (see the trigger endpoint).
        cache.delete(domain_scan_lock_key(organization_id, scanner_name))

    logger.info(
        "domain_scan_fanned_out",
        extra={
            "organization_id": str(organization_id),
            "scanner_name": scanner_name,
            "batch_id": str(batch_id),
            "jobs_queued": queued,
        },
    )
    return f"Queued {queued} {scanner_name} scan(s)."


def _create_and_enqueue(jobs: list[ScanJob]) -> int:
    if not jobs:
        return 0
    ScanJob.objects.bulk_create(jobs)
    for job in jobs:
        run_scan_job.delay(str(job.id))
    return len(jobs)

