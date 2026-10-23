from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.assets.models import Asset
from apps.findings.models import Finding
from apps.organizations.models import Organization
from apps.scanning.models import ScanJob
from apps.scanning.tasks import purge_old_scan_jobs


class ScanJobRetentionTests(TestCase):
    def setUp(self):
        org = Organization.objects.create(name="Acme", root_domain="acme.com")
        self.asset = Asset.objects.create(organization=org, value="shop.acme.com", asset_type=Asset.AssetType.SUBDOMAIN)
        self.org = org

    def job(self, days_ago, status):
        job = ScanJob.objects.create(organization=self.org, asset=self.asset, scanner_name="nmap", status=status,
                                     idempotency_key=f"{days_ago}-{status}")
        ScanJob.objects.filter(id=job.id).update(created_at=timezone.now() - timedelta(days=days_ago))
        return job

    @override_settings(SCAN_JOB_RETENTION_DAYS=90)
    def test_old_finished_jobs_go_and_their_findings_stay(self):
        old = self.job(120, ScanJob.Status.SUCCESS)
        self.job(100, ScanJob.Status.FAILED)
        stuck = self.job(120, ScanJob.Status.RUNNING)
        recent = self.job(10, ScanJob.Status.SUCCESS)
        finding = Finding.objects.create(asset=self.asset, scan_job=old, finding_type="open_port", severity="low",
                                         title="Open port 22", dedupe_key="x")
        self.assertIn("Deleted 2", purge_old_scan_jobs())
        self.assertEqual(set(ScanJob.objects.values_list("id", flat=True)), {stuck.id, recent.id})
        finding.refresh_from_db()
        self.assertIsNone(finding.scan_job)

    @override_settings(SCAN_JOB_RETENTION_DAYS=0)
    def test_zero_keeps_everything(self):
        self.job(400, ScanJob.Status.SUCCESS)
        self.assertEqual(purge_old_scan_jobs(), "Scan job retention is off.")
        self.assertEqual(ScanJob.objects.count(), 1)
