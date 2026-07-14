"""
Generic scan-execution task. This function is scanner-agnostic: it
looks up the right plugin by name, runs it, and reconciles the results
into Finding rows. Adding a new scanner never touches this file.
"""

from celery import shared_task
from django.utils import timezone

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

        seen_dedupe_keys = set()
        for rf in raw_findings:
            dedupe_key = Finding.build_dedupe_key(rf.finding_type, rf.identifier)
            Finding.objects.update_or_create(
                asset=scan_job.asset,
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
            seen_dedupe_keys.add(dedupe_key)

        # Anything this scanner owns that wasn't seen this run has been
        # resolved (e.g. a port that closed) -- flip it, don't delete it,
        # so historical diffing ("resolved today") stays queryable.
        if scanner.owned_finding_types:
            (
                Finding.objects.filter(
                    asset=scan_job.asset,
                    finding_type__in=scanner.owned_finding_types,
                    is_active=True,
                )
                .exclude(dedupe_key__in=seen_dedupe_keys)
                .update(is_active=False)
            )

        scan_job.status = ScanJob.Status.SUCCESS
        scan_job.finished_at = timezone.now()
        scan_job.save(update_fields=["status", "finished_at"])

    except Exception as exc:
        scan_job.status = ScanJob.Status.FAILED
        scan_job.error_message = str(exc)
        scan_job.finished_at = timezone.now()
        scan_job.save(update_fields=["status", "error_message", "finished_at"])
        raise self.retry(exc=exc)