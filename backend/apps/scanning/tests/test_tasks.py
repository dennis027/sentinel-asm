"""
Tests for run_scan_job orchestration logic: idempotency, force-retrigger,
finding upsert/reconciliation (both asset-level and org-level), and the
RETRYING vs terminal FAILED status distinction.

Scanner plugins are replaced with lightweight fakes via patching
get_scanner() -- these tests exercise the orchestration code in
tasks.py, not any real scanner's network/subprocess behavior (that's
covered separately in test_plugin_parsers.py and was verified manually
against live targets during development).
"""

from unittest.mock import patch

from django.test import TestCase

from apps.assets.models import Asset
from apps.findings.models import Finding
from apps.organizations.models import Organization
from apps.scanning.models import ScanJob
from apps.scanning.plugins.base import RawFinding
from apps.scanning.tasks import run_scan_job


def make_fake_scanner(findings=None, applies_to="asset", owned_types=None, raises=None):
    """Builds a fake scanner CLASS (not instance) matching the
    BaseScanner contract, for patching get_scanner()."""
    findings = findings or []
    owned_types = owned_types or []

    class FakeScanner:
        def run(self, target):
            if raises:
                raise raises
            return findings

        def extract_technologies(self, target):
            return []

    # Set as class attributes after creation rather than in the class
    # body -- class-body top-level statements don't get closure access
    # to the enclosing function's locals the way methods do.
    FakeScanner.applies_to = applies_to
    FakeScanner.owned_finding_types = owned_types
    FakeScanner.name = "fake_scanner"
    return FakeScanner


class IdempotencyAndForceTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", root_domain="test.com")
        self.asset = Asset.objects.create(
            organization=self.org, value="test.com", asset_type=Asset.AssetType.DOMAIN
        )

    def test_same_day_retrigger_reuses_existing_job(self):
        key = ScanJob.build_idempotency_key("nmap", self.asset.value)
        job1, created1 = ScanJob.objects.get_or_create(
            idempotency_key=key,
            defaults=dict(organization=self.org, asset=self.asset, scanner_name="nmap"),
        )
        job2, created2 = ScanJob.objects.get_or_create(
            idempotency_key=key,
            defaults=dict(organization=self.org, asset=self.asset, scanner_name="nmap"),
        )
        self.assertTrue(created1)
        self.assertFalse(created2)
        self.assertEqual(job1.id, job2.id)
        self.assertEqual(ScanJob.objects.count(), 1)

    def test_force_nonce_produces_unique_keys(self):
        import uuid
        key1 = ScanJob.build_idempotency_key("nmap", self.asset.value, nonce=uuid.uuid4().hex)
        key2 = ScanJob.build_idempotency_key("nmap", self.asset.value, nonce=uuid.uuid4().hex)
        self.assertNotEqual(key1, key2)

    def test_without_nonce_same_day_key_is_deterministic(self):
        key1 = ScanJob.build_idempotency_key("nmap", self.asset.value)
        key2 = ScanJob.build_idempotency_key("nmap", self.asset.value)
        self.assertEqual(key1, key2)


class AssetLevelReconciliationTests(TestCase):
    """Covers the nmap-style case: findings belong to one fixed asset."""

    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", root_domain="test.com")
        self.asset = Asset.objects.create(
            organization=self.org, value="test.com", asset_type=Asset.AssetType.DOMAIN
        )

    def _run(self, findings):
        fake_cls = make_fake_scanner(
            findings=findings, applies_to="asset",
            owned_types=[Finding.FindingType.OPEN_PORT],
        )
        scan_job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="nmap",
            idempotency_key=f"test-{ScanJob.objects.count()}",
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=fake_cls):
            with patch("apps.scanning.tasks.notify_new_findings.delay"):
                run_scan_job.run(str(scan_job.id))
        return scan_job

    def test_new_finding_is_created(self):
        rf = RawFinding(
            finding_type=Finding.FindingType.OPEN_PORT, identifier="443",
            severity=Finding.Severity.INFO, title="Open port 443",
        )
        self._run([rf])
        self.assertEqual(Finding.objects.filter(asset=self.asset, is_active=True).count(), 1)

    def test_finding_no_longer_returned_gets_resolved(self):
        rf_443 = RawFinding(
            finding_type=Finding.FindingType.OPEN_PORT, identifier="443",
            severity=Finding.Severity.INFO, title="Open port 443",
        )
        self._run([rf_443])
        # Second scan: port 443 no longer open.
        self._run([])

        finding = Finding.objects.get(asset=self.asset, dedupe_key=Finding.build_dedupe_key(
            Finding.FindingType.OPEN_PORT, "443"
        ))
        self.assertFalse(finding.is_active)

    def test_rescan_with_same_finding_bumps_last_seen_not_duplicate(self):
        rf = RawFinding(
            finding_type=Finding.FindingType.OPEN_PORT, identifier="443",
            severity=Finding.Severity.INFO, title="Open port 443",
        )
        self._run([rf])
        first_seen = Finding.objects.get(asset=self.asset).first_seen
        self._run([rf])  # same finding again

        self.assertEqual(Finding.objects.filter(asset=self.asset).count(), 1)
        finding = Finding.objects.get(asset=self.asset)
        self.assertEqual(finding.first_seen, first_seen)  # unchanged
        self.assertTrue(finding.is_active)

    def test_scan_job_marked_success(self):
        scan_job = self._run([])
        scan_job.refresh_from_db()
        self.assertEqual(scan_job.status, ScanJob.Status.SUCCESS)


class OrgLevelReconciliationTests(TestCase):
    """Covers the subfinder-style case: one scan produces findings across
    MULTIPLE, possibly brand-new assets -- the trickier reconciliation
    path since it can't just filter by a single fixed asset."""

    def setUp(self):
        self.org = Organization.objects.create(name="Acme", root_domain="acme.com")

    def _run(self, subdomains, idempotency_key):
        findings = [
            RawFinding(
                finding_type=Finding.FindingType.SUBDOMAIN_DISCOVERED,
                identifier="discovered", severity=Finding.Severity.INFO,
                title=f"Subdomain discovered: {sub}", asset_value=sub,
            )
            for sub in subdomains
        ]
        fake_cls = make_fake_scanner(
            findings=findings, applies_to="organization",
            owned_types=[Finding.FindingType.SUBDOMAIN_DISCOVERED],
        )
        scan_job = ScanJob.objects.create(
            organization=self.org, asset=None, scanner_name="subfinder",
            idempotency_key=idempotency_key,
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=fake_cls):
            with patch("apps.scanning.tasks.notify_new_findings.delay"):
                run_scan_job.run(str(scan_job.id))
        return scan_job

    def test_creates_new_assets_for_each_subdomain(self):
        self._run(["api.acme.com", "mail.acme.com"], "day1")
        self.assertEqual(Asset.objects.filter(organization=self.org).count(), 2)

    def test_reconciliation_resolves_correct_asset_only(self):
        self._run(["api.acme.com", "mail.acme.com", "vpn.acme.com"], "day1")
        # Day 2: vpn.acme.com no longer found.
        self._run(["api.acme.com", "mail.acme.com"], "day2")

        api_finding = Finding.objects.get(asset__value="api.acme.com")
        vpn_finding = Finding.objects.get(asset__value="vpn.acme.com")
        self.assertTrue(api_finding.is_active)
        self.assertFalse(vpn_finding.is_active)  # correctly resolved, not deleted

    def test_missing_asset_value_raises_for_org_level_scanner(self):
        bad_finding = RawFinding(
            finding_type=Finding.FindingType.SUBDOMAIN_DISCOVERED,
            identifier="discovered", severity=Finding.Severity.INFO,
            title="Broken finding",  # no asset_value set
        )
        fake_cls = make_fake_scanner(
            findings=[bad_finding], applies_to="organization",
            owned_types=[Finding.FindingType.SUBDOMAIN_DISCOVERED],
        )
        scan_job = ScanJob.objects.create(
            organization=self.org, asset=None, scanner_name="subfinder",
            idempotency_key="bad-finding-test",
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=fake_cls):
            run_scan_job.apply(args=[str(scan_job.id)])

        scan_job.refresh_from_db()
        self.assertEqual(scan_job.status, ScanJob.Status.FAILED)
        self.assertIn("asset_value", scan_job.error_message)


class RetryAndFailureStatusTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", root_domain="test.com")
        self.asset = Asset.objects.create(
            organization=self.org, value="test.com", asset_type=Asset.AssetType.DOMAIN
        )

    def test_transient_failure_then_success_ends_at_success(self):
        call_count = {"n": 0}

        class FlakyScanner:
            applies_to = "asset"
            owned_finding_types = []

            def run(self, target):
                call_count["n"] += 1
                if call_count["n"] < 3:
                    raise RuntimeError("transient")
                return []

            def extract_technologies(self, target):
                return []

        scan_job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="ssl_expiry",
            idempotency_key="flaky-test",
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=FlakyScanner):
            run_scan_job.apply(args=[str(scan_job.id)])

        scan_job.refresh_from_db()
        self.assertEqual(scan_job.status, ScanJob.Status.SUCCESS)
        self.assertEqual(call_count["n"], 3)

    def test_permanent_failure_ends_at_terminal_failed(self):
        class BrokenScanner:
            applies_to = "asset"
            owned_finding_types = []

            def run(self, target):
                raise RuntimeError("permanently broken")

            def extract_technologies(self, target):
                return []

        scan_job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="ssl_expiry",
            idempotency_key="broken-test",
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=BrokenScanner):
            run_scan_job.apply(args=[str(scan_job.id)])

        scan_job.refresh_from_db()
        self.assertEqual(scan_job.status, ScanJob.Status.FAILED)
        self.assertEqual(scan_job.error_message, "permanently broken")
        self.assertIsNotNone(scan_job.finished_at)


class NotificationTriggerTests(TestCase):
    """Confirms run_scan_job only calls notify_new_findings.delay() for
    genuinely NEW findings, never for re-confirmed ones."""

    def setUp(self):
        self.org = Organization.objects.create(name="Test Org", root_domain="test.com")
        self.asset = Asset.objects.create(
            organization=self.org, value="test.com", asset_type=Asset.AssetType.DOMAIN
        )

    def test_new_finding_triggers_notification_call(self):
        rf = RawFinding(
            finding_type=Finding.FindingType.OPEN_PORT, identifier="443",
            severity=Finding.Severity.INFO, title="Open port 443",
        )
        fake_cls = make_fake_scanner(findings=[rf], owned_types=[Finding.FindingType.OPEN_PORT])
        scan_job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="nmap",
            idempotency_key="notify-new-test",
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=fake_cls):
            with patch("apps.scanning.tasks.notify_new_findings.delay") as mock_notify:
                run_scan_job.run(str(scan_job.id))
        mock_notify.assert_called_once()
        called_finding_ids = mock_notify.call_args[0][1]
        self.assertEqual(len(called_finding_ids), 1)

    def test_reconfirmed_finding_does_not_trigger_notification(self):
        rf = RawFinding(
            finding_type=Finding.FindingType.OPEN_PORT, identifier="443",
            severity=Finding.Severity.INFO, title="Open port 443",
        )
        fake_cls = make_fake_scanner(findings=[rf], owned_types=[Finding.FindingType.OPEN_PORT])

        scan_job_1 = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="nmap",
            idempotency_key="notify-day1",
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=fake_cls):
            with patch("apps.scanning.tasks.notify_new_findings.delay"):
                run_scan_job.run(str(scan_job_1.id))

        scan_job_2 = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="nmap",
            idempotency_key="notify-day2",
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=fake_cls):
            with patch("apps.scanning.tasks.notify_new_findings.delay") as mock_notify_2:
                run_scan_job.run(str(scan_job_2.id))

        mock_notify_2.assert_not_called()