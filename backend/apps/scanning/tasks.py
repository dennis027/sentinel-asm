"""
Generic scan-execution task. This function is scanner-agnostic: it
looks up the right plugin by name, runs it, and reconciles the results
into Finding rows. Adding a new scanner never touches this file.
"""

from celery import shared_task
from django.utils import timezone

from apps.assets.models import Asset
from apps.findings.models import Finding

from .models import ScanJob
from .plugins.registry import get_scanner


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def run_scan_job(self, scan_job_id: str):
    scan_job = ScanJob.objects.select_related("asset", "organization").get(id=scan_job_id)

    scan_job.status = ScanJob.Status.RUNNING
    scan_job.started_at = timezone.now()
    scan_job.celery_task_id = self.request.id or ""
    scan_job.save(update_fields=["status", "started_at", "celery_task_id"])

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
            Finding.objects.update_or_create(
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

        scan_job.status = ScanJob.Status.SUCCESS
        scan_job.finished_at = timezone.now()
        scan_job.save(update_fields=["status", "finished_at"])

    except Exception as exc:
        scan_job.status = ScanJob.Status.FAILED
        scan_job.error_message = str(exc)
        scan_job.finished_at = timezone.now()
        scan_job.save(update_fields=["status", "error_message", "finished_at"])
        raise self.retry(exc=exc)