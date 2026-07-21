"""
Cross-tenant data isolation tests. This is the actual regression guard
for the vulnerability this module fixed: before org-scoping existed,
any authenticated user could see and act on EVERY organization's data,
not just their own.
"""

from django.contrib.auth.models import User
from django.test import TestCase

from apps.assets.models import Asset
from apps.findings.models import Finding
from apps.notifications.models import NotificationRule
from apps.organizations.models import Membership, Organization
from apps.scanning.models import ScanJob


class CrossTenantIsolationTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="pass123")
        self.bob = User.objects.create_user("bob", password="pass123")

        self.org_a = Organization.objects.create(name="Alice Corp", root_domain="alicecorp.com")
        self.org_b = Organization.objects.create(name="Bob Corp", root_domain="bobcorp.com")
        Membership.objects.create(user=self.alice, organization=self.org_a, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.bob, organization=self.org_b, role=Membership.Role.OWNER)

        self.asset_a = Asset.objects.create(
            organization=self.org_a, value="alicecorp.com", asset_type=Asset.AssetType.DOMAIN
        )
        self.asset_b = Asset.objects.create(
            organization=self.org_b, value="bobcorp.com", asset_type=Asset.AssetType.DOMAIN
        )

        self.client.force_login(self.alice)

    def test_organization_list_excludes_other_orgs(self):
        response = self.client.get("/api/organizations/")
        names = [o["name"] for o in response.json()["results"]]
        self.assertEqual(names, ["Alice Corp"])

    def test_organization_detail_of_other_org_404s(self):
        response = self.client.get(f"/api/organizations/{self.org_b.id}/")
        self.assertEqual(response.status_code, 404)

    def test_asset_list_excludes_other_orgs_assets(self):
        response = self.client.get("/api/assets/")
        values = [a["value"] for a in response.json()["results"]]
        self.assertEqual(values, ["alicecorp.com"])

    def test_asset_detail_of_other_org_404s(self):
        response = self.client.get(f"/api/assets/{self.asset_b.id}/")
        self.assertEqual(response.status_code, 404)

    def test_finding_list_excludes_other_orgs_findings(self):
        scan_job = ScanJob.objects.create(
            organization=self.org_b, asset=self.asset_b, scanner_name="nmap", idempotency_key="bob-scan",
        )
        Finding.objects.create(
            scan_job=scan_job, asset=self.asset_b, finding_type=Finding.FindingType.OPEN_PORT,
            severity=Finding.Severity.HIGH, title="Bob's finding", dedupe_key="bob-finding",
        )
        response = self.client.get("/api/findings/")
        self.assertEqual(response.json()["count"], 0)

    def test_cannot_trigger_scan_against_other_orgs_asset(self):
        """The actual vulnerability this module fixes: before this,
        any authenticated user could trigger a scan against ANY asset,
        regardless of which org owned it."""
        response = self.client.post(
            "/api/scan-jobs/trigger/",
            data={"scanner_name": "ssl_expiry", "asset_id": str(self.asset_b.id)},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(ScanJob.objects.filter(asset=self.asset_b).count(), 0)

    def test_can_trigger_scan_against_own_orgs_asset(self):
        from unittest.mock import patch
        with patch("apps.api.views.run_scan_job.delay"):
            response = self.client.post(
                "/api/scan-jobs/trigger/",
                data={"scanner_name": "ssl_expiry", "asset_id": str(self.asset_a.id)},
                content_type="application/json",
            )
        self.assertIn(response.status_code, (200, 201))

    def test_notification_rule_creation_rejected_for_other_org(self):
        response = self.client.post(
            "/api/notification-rules/",
            data={"organization": str(self.org_b.id), "recipient_email": "hacker@example.com", "min_severity": "info"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(NotificationRule.objects.filter(organization=self.org_b).exists())

    def test_creating_org_auto_assigns_owner_membership(self):
        response = self.client.post(
            "/api/organizations/",
            data={"name": "New Org", "root_domain": "neworg.com"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        new_org_id = response.json()["id"]
        membership = Membership.objects.get(user=self.alice, organization_id=new_org_id)
        self.assertEqual(membership.role, Membership.Role.OWNER)

    def test_superuser_sees_all_organizations(self):
        admin = User.objects.create_superuser("admin", password="adminpass123")
        self.client.force_login(admin)
        response = self.client.get("/api/organizations/")
        self.assertEqual(response.json()["count"], 2)