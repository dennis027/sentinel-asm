import shutil
import tempfile
from io import StringIO
from pathlib import Path

from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings

from apps.findings.models import Finding, RiskSnapshot
from apps.findings.summary import build_risk_summary
from apps.organizations.models import Membership, Organization


class LoadDemoDataTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("presenter", password="x-pass-12345")
        self.media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media)
        override = override_settings(MEDIA_ROOT=self.media)
        override.enable()
        self.addCleanup(override.disable)

    def load(self, *extra):
        call_command("load_demo_data", "--owner", "presenter", *extra, stdout=StringIO())
        return Organization.objects.get(root_domain="acme-retail.example")

    def test_builds_a_complete_believable_organization(self):
        org = self.load()
        self.assertTrue(org.is_domain_verified)
        self.assertEqual(Membership.objects.get(organization=org, user=self.owner).role, "owner")
        self.assertEqual(org.assets.count(), 46)

        issues = Finding.objects.filter(asset__organization=org).exclude(finding_type__in=Finding.INVENTORY_TYPES)
        self.assertGreater(issues.counts_toward_risk().count(), 15)
        self.assertGreater(issues.filter(is_active=False, resolved_at__isnull=False).count(), 5)
        self.assertTrue(issues.filter(assignee__isnull=False).exists())
        self.assertTrue(Finding.objects.filter(asset__organization=org, finding_type="screenshot").exists())
        self.assertTrue(any(Path(self.media, "screenshots").rglob("*.png")))

        snapshots = RiskSnapshot.objects.filter(organization=org).order_by("date")
        self.assertEqual(snapshots.count(), 91)
        # The story: worse three months ago than today.
        self.assertLess(snapshots.first().score, snapshots.last().score)
        self.assertEqual(snapshots.last().score, build_risk_summary(org)["average_risk_score"])
        self.assertTrue(org.activity.exists())

    def test_includes_known_exploited_findings_and_application_logs(self):
        from apps.findings.insights import build_fix_plan
        from apps.logs.models import ErrorGroup, LogDetection

        org = self.load()
        self.assertTrue(Finding.objects.filter(asset__organization=org, cves__contains=["CVE-2023-4966"]).exists())
        self.assertEqual(build_fix_plan(org)["steps"][0]["known_exploited"], 1)

        groups = ErrorGroup.objects.filter(organization=org)
        self.assertEqual(set(groups.values_list("source__name", flat=True)), {"shop-api", "payments", "storefront"})
        deadlock = groups.get(source__name="storefront")
        self.assertEqual((deadlock.count, deadlock.culprit),
                         (6, "app/Services/StockReservation.php in Illuminate\\Database\\Query\\Builder->update"))
        self.assertEqual(groups.get(exception_type="TypeError").regressions, 1)
        rules = set(LogDetection.objects.filter(source__organization=org, source__os__in=["python", "node"])
                    .values_list("rule", flat=True))
        self.assertLessEqual({"new_error", "error_regressed", "server_errors_spike", "attack_probes",
                              "secrets_logged", "brute_force"}, rules)

        # Releases: the checkout bug arrived with 2.15.0, the refund bug came back in 3.8.2.
        self.assertEqual(groups.get(exception_type="KeyError").first_release, "2.15.0")
        refund = groups.get(exception_type="TypeError")
        self.assertEqual((refund.first_release, refund.last_release), ("3.8.1", "3.8.2"))
        # The team's own alert fired on the gateway outage.
        from apps.logs.models import LogAlertRule

        alert = LogAlertRule.objects.get(organization=org, name="Card gateway timing out")
        self.assertTrue(LogDetection.objects.filter(rule=alert.rule_id).exists())

    def test_includes_the_newest_checks(self):
        org = self.load()
        kinds = set(Finding.objects.filter(asset__organization=org).values_list("finding_type", flat=True))
        self.assertLessEqual({"exposed_secret", "public_bucket", "domain_registration"}, kinds)

    def test_reset_replaces_it_and_a_second_load_without_reset_is_refused(self):
        self.load()
        with self.assertRaises(CommandError):
            self.load()
        self.load("--reset")
        self.assertEqual(Organization.objects.filter(root_domain="acme-retail.example").count(), 1)

    def test_unknown_owner_is_a_clear_error(self):
        with self.assertRaises(CommandError):
            call_command("load_demo_data", "--owner", "nobody", stdout=StringIO())
