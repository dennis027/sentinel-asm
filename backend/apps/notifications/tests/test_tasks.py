"""
Tests for notify_new_findings: severity-threshold filtering, the
no-active-rules early-exit, and multiple rules on the same org getting
independently evaluated.
"""

from django.core import mail
from django.test import TestCase, override_settings

from apps.assets.models import Asset
from apps.findings.models import Finding
from apps.notifications.models import NotificationRule
from apps.notifications.tasks import notify_new_findings
from apps.organizations.models import Organization
from apps.scanning.models import ScanJob

# locmem backend populates django.core.mail.outbox, which is what makes
# these assertions possible -- the real app defaults to console/smtp,
# this override is test-only.
EMAIL_TEST_SETTINGS = override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")


@EMAIL_TEST_SETTINGS
class NotificationDispatchTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", root_domain="acme.com")
        self.asset = Asset.objects.create(
            organization=self.org, value="acme.com", asset_type=Asset.AssetType.DOMAIN
        )
        self.scan_job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="nmap",
            idempotency_key="notif-test-job",
        )
        mail.outbox = []

    def _make_finding(self, severity, dedupe_key):
        return Finding.objects.create(
            scan_job=self.scan_job, asset=self.asset,
            finding_type=Finding.FindingType.OPEN_PORT, severity=severity,
            title=f"Test finding ({severity})", dedupe_key=dedupe_key,
        )

    def test_no_rules_sends_nothing(self):
        finding = self._make_finding(Finding.Severity.CRITICAL, "no-rules-key")
        result = notify_new_findings.run(str(self.scan_job.id), [str(finding.id)])
        self.assertEqual(len(mail.outbox), 0)
        self.assertIn("No active notification rules", result)

    def test_empty_finding_ids_short_circuits(self):
        result = notify_new_findings.run(str(self.scan_job.id), [])
        self.assertEqual(len(mail.outbox), 0)
        self.assertIn("nothing to notify", result)

    def test_severity_below_threshold_not_sent(self):
        NotificationRule.objects.create(
            organization=self.org, recipient_email="a@example.com",
            min_severity=Finding.Severity.HIGH,
        )
        finding = self._make_finding(Finding.Severity.LOW, "below-threshold-key")
        notify_new_findings.run(str(self.scan_job.id), [str(finding.id)])
        self.assertEqual(len(mail.outbox), 0)

    def test_severity_at_threshold_is_sent(self):
        NotificationRule.objects.create(
            organization=self.org, recipient_email="a@example.com",
            min_severity=Finding.Severity.HIGH,
        )
        finding = self._make_finding(Finding.Severity.HIGH, "at-threshold-key")
        notify_new_findings.run(str(self.scan_job.id), [str(finding.id)])
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["a@example.com"])

    def test_severity_above_threshold_is_sent(self):
        NotificationRule.objects.create(
            organization=self.org, recipient_email="a@example.com",
            min_severity=Finding.Severity.MEDIUM,
        )
        finding = self._make_finding(Finding.Severity.CRITICAL, "above-threshold-key")
        notify_new_findings.run(str(self.scan_job.id), [str(finding.id)])
        self.assertEqual(len(mail.outbox), 1)

    def test_inactive_rule_is_skipped(self):
        NotificationRule.objects.create(
            organization=self.org, recipient_email="a@example.com",
            min_severity=Finding.Severity.INFO, is_active=False,
        )
        finding = self._make_finding(Finding.Severity.CRITICAL, "inactive-rule-key")
        notify_new_findings.run(str(self.scan_job.id), [str(finding.id)])
        self.assertEqual(len(mail.outbox), 0)

    def test_multiple_rules_each_evaluated_independently(self):
        NotificationRule.objects.create(
            organization=self.org, recipient_email="everything@example.com",
            min_severity=Finding.Severity.INFO,
        )
        NotificationRule.objects.create(
            organization=self.org, recipient_email="critical-only@example.com",
            min_severity=Finding.Severity.CRITICAL,
        )
        finding = self._make_finding(Finding.Severity.MEDIUM, "multi-rule-key")
        notify_new_findings.run(str(self.scan_job.id), [str(finding.id)])

        # Only the low-threshold rule's recipient should get an email --
        # the critical-only rule shouldn't match a MEDIUM finding.
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["everything@example.com"])

    def test_rule_on_different_org_is_not_used(self):
        other_org = Organization.objects.create(name="Other Corp", root_domain="other.com")
        NotificationRule.objects.create(
            organization=other_org, recipient_email="wrong-org@example.com",
            min_severity=Finding.Severity.INFO,
        )
        finding = self._make_finding(Finding.Severity.CRITICAL, "cross-org-key")
        notify_new_findings.run(str(self.scan_job.id), [str(finding.id)])
        self.assertEqual(len(mail.outbox), 0)

    def test_email_content_includes_finding_titles(self):
        NotificationRule.objects.create(
            organization=self.org, recipient_email="a@example.com",
            min_severity=Finding.Severity.INFO,
        )
        finding = self._make_finding(Finding.Severity.HIGH, "content-check-key")
        notify_new_findings.run(str(self.scan_job.id), [str(finding.id)])
        self.assertIn(finding.title, mail.outbox[0].body)
        self.assertIn(self.org.name, mail.outbox[0].subject)