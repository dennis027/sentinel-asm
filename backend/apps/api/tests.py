"""
API-level tests: role enforcement, domain verification, scan-target
guards, finding triage, screenshot access, and the auth endpoints.
Tenant isolation (who can SEE what) lives in
apps/organizations/tests/test_permissions.py; this file covers what a
member is allowed to DO, plus everything that hangs off the HTTP layer.
"""

import shutil
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rest_framework import serializers

from apps.assets.models import Asset
from apps.audit_logs.models import AuthEvent
from apps.audit_logs.utils import get_client_ip
from apps.findings.models import Finding
from apps.notifications.models import NotificationRule
from apps.organizations.models import Membership, Organization
from apps.scanning.models import ScanJob
from apps.scanning.plugins.base import RawFinding
from apps.scanning.targets import TargetNotAllowed, assert_public_target, validate_root_domain
from apps.scanning.tasks import fan_out_domain_scan, reap_stale_scan_jobs, run_scan_job, trigger_daily_scans

JSON = "application/json"


def make_finding(asset, title="Open port 22/tcp", severity=Finding.Severity.HIGH, **extra):
    return Finding.objects.create(
        asset=asset,
        finding_type=extra.pop("finding_type", Finding.FindingType.OPEN_PORT),
        severity=severity,
        title=title,
        dedupe_key=Finding.build_dedupe_key("test", title),
        **extra,
    )


class OrgTestCase(TestCase):
    """One organization with a user in each role, plus an outsider."""

    # Built once per class, not per test -- hashing five passwords for
    # every test method is most of this file's runtime otherwise.
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Acme", root_domain="acme.com")
        cls.asset = Asset.objects.create(
            organization=cls.org, value="acme.com", asset_type=Asset.AssetType.DOMAIN
        )
        cls.users = {}
        for role in Membership.Role.values:
            user = User.objects.create_user(role, password="pass12345!")
            Membership.objects.create(user=user, organization=cls.org, role=role)
            cls.users[role] = user
        cls.outsider = User.objects.create_user("outsider", password="pass12345!")

    def login(self, role):
        self.client.force_login(self.users[role])


@override_settings(REQUIRE_DOMAIN_VERIFICATION=False)
class RoleEnforcementTests(OrgTestCase):
    def trigger(self):
        with patch("apps.api.views.run_scan_job.delay"):
            return self.client.post(
                "/api/scan-jobs/trigger/",
                data={"scanner_name": "ssl_expiry", "asset_id": str(self.asset.id)},
                content_type=JSON,
            )

    def test_viewer_can_read_but_not_trigger_scans(self):
        self.login("viewer")
        self.assertEqual(self.client.get("/api/assets/").status_code, 200)
        self.assertEqual(self.trigger().status_code, 403)
        self.assertFalse(ScanJob.objects.exists())

    def test_analyst_can_trigger_scans(self):
        self.login("analyst")
        self.assertEqual(self.trigger().status_code, 201)

    def test_only_admin_and_owner_can_edit_the_organization(self):
        for role, expected in [("viewer", 403), ("analyst", 403), ("admin", 200), ("owner", 200)]:
            with self.subTest(role=role):
                self.login(role)
                response = self.client.patch(
                    f"/api/organizations/{self.org.id}/", data={"name": f"Renamed by {role}"},
                    content_type=JSON,
                )
                self.assertEqual(response.status_code, expected)

    def test_only_owner_can_delete_the_organization(self):
        for role in ("viewer", "analyst", "admin"):
            with self.subTest(role=role):
                self.login(role)
                response = self.client.delete(f"/api/organizations/{self.org.id}/")
                self.assertEqual(response.status_code, 403)
        self.assertTrue(Organization.objects.filter(id=self.org.id).exists())

        self.login("owner")
        self.assertEqual(self.client.delete(f"/api/organizations/{self.org.id}/").status_code, 204)

    def test_root_domain_cannot_be_changed_after_creation(self):
        self.login("owner")
        response = self.client.patch(
            f"/api/organizations/{self.org.id}/", data={"root_domain": "someone-else.com"},
            content_type=JSON,
        )
        self.assertEqual(response.status_code, 400)
        self.org.refresh_from_db()
        self.assertEqual(self.org.root_domain, "acme.com")

    def test_notification_rules_need_admin(self):
        payload = {"organization": str(self.org.id), "recipient_email": "sec@acme.com"}
        self.login("analyst")
        self.assertEqual(
            self.client.post("/api/notification-rules/", data=payload, content_type=JSON).status_code, 403
        )

        self.login("admin")
        created = self.client.post("/api/notification-rules/", data=payload, content_type=JSON)
        self.assertEqual(created.status_code, 201)
        rule_id = created.json()["id"]

        self.login("analyst")
        self.assertEqual(self.client.delete(f"/api/notification-rules/{rule_id}/").status_code, 403)
        self.assertEqual(
            self.client.patch(
                f"/api/notification-rules/{rule_id}/", data={"is_active": False}, content_type=JSON
            ).status_code,
            403,
        )
        self.assertTrue(NotificationRule.objects.get(id=rule_id).is_active)

    def test_organization_reports_the_callers_role(self):
        self.login("analyst")
        response = self.client.get(f"/api/organizations/{self.org.id}/")
        self.assertEqual(response.json()["my_role"], "analyst")


class NotificationRuleTenantTests(TestCase):
    def test_rule_cannot_be_moved_into_another_organization(self):
        """A member of one org re-pointing their rule at another org
        would start receiving that org's findings by email."""
        mallory = User.objects.create_user("mallory", password="pass12345!")
        own_org = Organization.objects.create(name="Mallory Inc", root_domain="mallory.com")
        victim_org = Organization.objects.create(name="Victim", root_domain="victim.com")
        Membership.objects.create(user=mallory, organization=own_org, role=Membership.Role.OWNER)
        rule = NotificationRule.objects.create(organization=own_org, recipient_email="m@mallory.com")

        self.client.force_login(mallory)
        for method in (self.client.patch, self.client.put):
            with self.subTest(method=method.__name__):
                response = method(
                    f"/api/notification-rules/{rule.id}/",
                    data={
                        "organization": str(victim_org.id),
                        "recipient_email": "m@mallory.com",
                        "min_severity": "info",
                    },
                    content_type=JSON,
                )
                self.assertEqual(response.status_code, 400)
                rule.refresh_from_db()
                self.assertEqual(rule.organization, own_org)


class OrganizationCreationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("carol", password="pass12345!")
        self.client.force_login(self.user)

    def create(self, root_domain):
        return self.client.post(
            "/api/organizations/", data={"name": "New", "root_domain": root_domain}, content_type=JSON
        )

    def test_creating_an_org_creates_its_root_domain_asset(self):
        response = self.create("Example.COM")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["root_domain"], "example.com")
        asset = Asset.objects.get(organization_id=response.json()["id"])
        self.assertEqual((asset.value, asset.asset_type), ("example.com", Asset.AssetType.DOMAIN))

    def test_internal_and_malformed_domains_are_rejected(self):
        for bad in ["localhost", "db", "redis", "10.0.0.5", "169.254.169.254", "intranet.local",
                    "api.internal", "http://example.com", "example.com/path", "exa mple.com", ""]:
            with self.subTest(root_domain=bad):
                self.assertEqual(self.create(bad).status_code, 400)
        self.assertFalse(Organization.objects.exists())


class RootDomainValidatorTests(SimpleTestCase):
    def test_normalizes_case_whitespace_and_trailing_dot(self):
        self.assertEqual(validate_root_domain("  Sub.Example.co.uk. "), "sub.example.co.uk")

    def test_rejects_ip_addresses(self):
        with self.assertRaises(serializers.ValidationError):
            validate_root_domain("203.0.113.5")


class PublicTargetGuardTests(SimpleTestCase):
    def resolving_to(self, *addresses):
        infos = [(None, None, None, "", (address, 0)) for address in addresses]
        return patch("apps.scanning.targets.socket.getaddrinfo", return_value=infos)

    def test_public_address_is_allowed(self):
        with self.resolving_to("93.184.216.34"):
            assert_public_target("example.com")

    def test_private_loopback_and_metadata_addresses_are_refused(self):
        for address in ["127.0.0.1", "10.1.2.3", "192.168.1.10", "172.17.0.2", "169.254.169.254", "::1"]:
            with self.subTest(address=address), self.resolving_to(address):
                with self.assertRaises(TargetNotAllowed):
                    assert_public_target("sneaky.example.com")

    def test_refused_if_any_resolved_address_is_private(self):
        with self.resolving_to("93.184.216.34", "10.0.0.1"), self.assertRaises(TargetNotAllowed):
            assert_public_target("mixed.example.com")

    def test_literal_private_ip_is_refused_without_a_lookup(self):
        with patch("apps.scanning.targets.socket.getaddrinfo") as getaddrinfo:
            with self.assertRaises(TargetNotAllowed):
                assert_public_target("192.168.0.1")
        getaddrinfo.assert_not_called()

    def test_unresolvable_host_is_left_to_the_scanner(self):
        with patch("apps.scanning.targets.socket.getaddrinfo", side_effect=OSError):
            assert_public_target("gone.example.com")

    @override_settings(ALLOW_PRIVATE_SCAN_TARGETS=True)
    def test_can_be_switched_off_for_lab_use(self):
        with self.resolving_to("10.0.0.1"):
            assert_public_target("lab.example.com")


class RefusedTargetScanJobTests(OrgTestCase):
    def test_job_fails_immediately_without_running_the_scanner_or_retrying(self):
        class Scanner:
            name = "fake"
            applies_to = "asset"
            owned_finding_types = []
            run_called = False

            def run(self, target):
                Scanner.run_called = True
                return []

            def extract_technologies(self, target):
                return []

        job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="fake", idempotency_key="refused"
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=Scanner), patch(
            "apps.scanning.tasks.assert_public_target", side_effect=TargetNotAllowed("acme.com is private")
        ):
            run_scan_job.apply(args=[str(job.id)])

        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.FAILED)
        self.assertIn("private", job.error_message)
        self.assertFalse(Scanner.run_called)


@override_settings(REQUIRE_DOMAIN_VERIFICATION=True)
class DomainVerificationTests(OrgTestCase):
    def trigger(self):
        with patch("apps.api.views.run_scan_job.delay") as delay:
            response = self.client.post(
                "/api/scan-jobs/trigger/",
                data={"scanner_name": "ssl_expiry", "asset_id": str(self.asset.id)},
                content_type=JSON,
            )
        return response, delay

    def test_unverified_org_cannot_be_scanned(self):
        self.login("owner")
        response, delay = self.trigger()
        self.assertEqual(response.status_code, 403)
        delay.assert_not_called()
        self.assertFalse(ScanJob.objects.exists())

    def test_verify_fails_without_the_txt_record(self):
        self.login("owner")
        with patch("apps.api.views.has_verification_record", return_value=False):
            response = self.client.post(f"/api/organizations/{self.org.id}/verify-domain/")
        self.assertEqual(response.status_code, 400)
        self.org.refresh_from_db()
        self.assertFalse(self.org.is_domain_verified)

    def test_verify_succeeds_with_the_txt_record_and_unlocks_scanning(self):
        self.login("owner")
        with patch("apps.api.views.has_verification_record", return_value=True):
            response = self.client.post(f"/api/organizations/{self.org.id}/verify-domain/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["domain_verified"])
        self.assertTrue(response.json()["scans_allowed"])

        response, delay = self.trigger()
        self.assertEqual(response.status_code, 201)
        delay.assert_called_once()

    def test_verify_needs_admin(self):
        self.login("analyst")
        with patch("apps.api.views.has_verification_record", return_value=True):
            response = self.client.post(f"/api/organizations/{self.org.id}/verify-domain/")
        self.assertEqual(response.status_code, 403)

    def test_each_org_gets_its_own_token_in_the_record_value(self):
        other = Organization.objects.create(name="Other", root_domain="other.com")
        self.assertNotEqual(self.org.verification_token, other.verification_token)
        self.assertEqual(self.org.verification_record_name, "_sentinel-asm.acme.com")
        self.assertIn(self.org.verification_token, self.org.verification_record_value)

    def test_daily_scans_skip_unverified_orgs(self):
        verified = Organization.objects.create(
            name="Verified", root_domain="verified.com", domain_verified_at=timezone.now()
        )
        with patch("apps.scanning.tasks.run_scan_job.delay"):
            trigger_daily_scans()
        self.assertFalse(ScanJob.objects.filter(organization=self.org).exists())
        self.assertTrue(ScanJob.objects.filter(organization=verified).exists())


class FindingTriageTests(OrgTestCase):
    def setUp(self):
        super().setUp()
        self.finding = make_finding(self.asset)

    def triage(self, status, note=""):
        return self.client.post(
            f"/api/findings/{self.finding.id}/triage/", data={"status": status, "note": note},
            content_type=JSON,
        )

    def test_viewer_cannot_triage(self):
        self.login("viewer")
        self.assertEqual(self.triage("accepted").status_code, 403)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, Finding.Status.OPEN)

    def test_analyst_can_triage_and_it_is_attributed(self):
        self.login("analyst")
        response = self.triage("false_positive", "Scanner hit the load balancer")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "false_positive")
        self.assertEqual(body["status_note"], "Scanner hit the load balancer")
        self.assertEqual(body["status_changed_by"], "analyst")
        self.assertIsNotNone(body["status_changed_at"])

    def test_invalid_status_is_rejected(self):
        self.login("analyst")
        self.assertEqual(self.triage("ignored").status_code, 400)

    def test_cannot_triage_another_orgs_finding(self):
        self.client.force_login(self.outsider)
        self.assertEqual(self.triage("accepted").status_code, 404)

    def test_triaged_findings_stop_counting_toward_risk(self):
        self.assertEqual(self.asset.risk_score, 84)  # high issue caps it at B
        self.login("analyst")
        self.triage("accepted")
        self.assertEqual(Asset.objects.get(id=self.asset.id).risk_score, 100)

        summary = self.client.get(f"/api/organizations/{self.org.id}/risk-summary/").json()
        self.assertEqual(summary["active_findings_by_severity"]["high"], 0)
        self.assertEqual(summary["average_risk_score"], 100)

    def test_verdict_survives_a_rescan(self):
        self.login("analyst")
        self.triage("accepted")

        class Scanner:
            name = "fake"
            applies_to = "asset"
            owned_finding_types = [Finding.FindingType.OPEN_PORT]

            def run(self, target):
                return [RawFinding(
                    finding_type=Finding.FindingType.OPEN_PORT, identifier="22/tcp",
                    severity=Finding.Severity.HIGH, title="Open port 22/tcp",
                )]

            def extract_technologies(self, target):
                return []

        Finding.objects.filter(id=self.finding.id).update(
            dedupe_key=Finding.build_dedupe_key(Finding.FindingType.OPEN_PORT, "22/tcp")
        )
        job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="fake", idempotency_key="rescan"
        )
        with patch("apps.scanning.tasks.get_scanner", return_value=Scanner), patch(
            "apps.scanning.tasks.assert_public_target"
        ):
            run_scan_job.apply(args=[str(job.id)])

        self.finding.refresh_from_db()
        self.assertTrue(self.finding.is_active)
        self.assertEqual(self.finding.status, Finding.Status.ACCEPTED)

    def test_triaged_filter(self):
        other = make_finding(self.asset, title="Open port 80/tcp")
        self.login("analyst")
        self.triage("accepted")

        triaged = self.client.get("/api/findings/?triaged=true").json()["results"]
        still_open = self.client.get("/api/findings/?triaged=false").json()["results"]
        self.assertEqual([f["id"] for f in triaged], [str(self.finding.id)])
        self.assertEqual([f["id"] for f in still_open], [str(other.id)])


class FindingOrganizationFilterTests(TestCase):
    def test_user_in_two_orgs_can_list_one_orgs_findings(self):
        user = User.objects.create_user("dana", password="pass12345!")
        findings = {}
        for name in ("one", "two"):
            org = Organization.objects.create(name=name, root_domain=f"{name}.com")
            Membership.objects.create(user=user, organization=org, role=Membership.Role.VIEWER)
            asset = Asset.objects.create(organization=org, value=f"{name}.com", asset_type="domain")
            findings[name] = (org, make_finding(asset, title=f"Finding in {name}"))

        self.client.force_login(user)
        self.assertEqual(self.client.get("/api/findings/").json()["count"], 2)

        org, finding = findings["one"]
        response = self.client.get(f"/api/findings/?organization={org.id}").json()
        self.assertEqual([f["id"] for f in response["results"]], [str(finding.id)])


class AssetListQueryCountTests(OrgTestCase):
    def test_risk_scores_do_not_cost_a_query_per_asset(self):
        for i in range(10):
            asset = Asset.objects.create(
                organization=self.org, value=f"host{i}.acme.com", asset_type="subdomain"
            )
            make_finding(asset, title=f"Finding {i}")
        self.login("viewer")

        # Fixed cost regardless of asset count: session, user, count,
        # assets, technologies, findings.
        with self.assertNumQueries(6):
            response = self.client.get("/api/assets/")
        self.assertEqual(response.json()["count"], 11)
        grades = {a["value"]: a["risk_grade"] for a in response.json()["results"]}
        self.assertEqual(grades["acme.com"], "A+")
        self.assertEqual(grades["host0.acme.com"], "B")  # an open high issue caps it


class PaginationTests(OrgTestCase):
    def test_page_size_can_be_raised_up_to_the_cap(self):
        Asset.objects.bulk_create(
            Asset(organization=self.org, value=f"h{i}.acme.com", asset_type="subdomain")
            for i in range(30)
        )
        self.login("viewer")
        self.assertEqual(len(self.client.get("/api/assets/").json()["results"]), 25)
        self.assertEqual(len(self.client.get("/api/assets/?page_size=200").json()["results"]), 31)
        self.assertEqual(len(self.client.get("/api/assets/?page=2").json()["results"]), 6)


class ScreenshotEndpointTests(OrgTestCase):
    PNG = b"\x89PNG\r\n\x1a\n fake image bytes"

    def setUp(self):
        super().setUp()
        self.media_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media_root)
        settings_override = override_settings(MEDIA_ROOT=self.media_root)
        settings_override.enable()
        self.addCleanup(settings_override.disable)

        relative = f"screenshots/{self.asset.id}/shot.png"
        path = Path(self.media_root) / relative
        path.parent.mkdir(parents=True)
        path.write_bytes(self.PNG)
        self.finding = make_finding(
            self.asset, title="Screenshot", finding_type=Finding.FindingType.SCREENSHOT,
            severity=Finding.Severity.INFO, raw_data={"screenshot_path": relative},
        )
        self.url = f"/api/findings/{self.finding.id}/screenshot/"

    def test_member_gets_the_image(self):
        self.login("viewer")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/png")
        self.assertEqual(b"".join(response.streaming_content), self.PNG)

    def test_anonymous_and_other_orgs_are_refused(self):
        self.assertIn(self.client.get(self.url).status_code, (401, 403))
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_media_is_no_longer_publicly_served(self):
        response = self.client.get(f"/media/screenshots/{self.asset.id}/shot.png")
        self.assertEqual(response.status_code, 404)

    def test_path_cannot_escape_the_screenshots_directory(self):
        secret = Path(self.media_root) / "secret.txt"
        secret.write_text("not a screenshot")
        self.finding.raw_data = {"screenshot_path": "screenshots/../secret.txt"}
        self.finding.save()
        self.login("viewer")
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_non_screenshot_finding_404s(self):
        other = make_finding(self.asset, title="Open port 443/tcp")
        self.login("viewer")
        self.assertEqual(self.client.get(f"/api/findings/{other.id}/screenshot/").status_code, 404)


class StaleScanJobReaperTests(OrgTestCase):
    def make_job(self, key, status, started_minutes_ago=None, created_hours_ago=0):
        job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="nmap", idempotency_key=key,
            status=status,
            started_at=(
                timezone.now() - timedelta(minutes=started_minutes_ago)
                if started_minutes_ago is not None else None
            ),
        )
        ScanJob.objects.filter(id=job.id).update(
            created_at=timezone.now() - timedelta(hours=created_hours_ago)
        )
        return job

    @override_settings(SCAN_JOB_STALE_AFTER_MINUTES=30)
    def test_only_jobs_that_cannot_still_be_running_are_failed(self):
        dead = self.make_job("dead", ScanJob.Status.RUNNING, started_minutes_ago=45)
        dead_retry = self.make_job("dead-retry", ScanJob.Status.RETRYING, started_minutes_ago=90)
        lost = self.make_job("lost", ScanJob.Status.PENDING, created_hours_ago=30)
        running = self.make_job("running", ScanJob.Status.RUNNING, started_minutes_ago=5)
        queued = self.make_job("queued", ScanJob.Status.PENDING, created_hours_ago=3)
        done = self.make_job("done", ScanJob.Status.SUCCESS, started_minutes_ago=600)

        reap_stale_scan_jobs()

        def status(job):
            job.refresh_from_db()
            return job.status

        for job in (dead, dead_retry, lost):
            self.assertEqual(status(job), ScanJob.Status.FAILED)
            self.assertTrue(job.error_message)
            self.assertIsNotNone(job.finished_at)
        self.assertEqual(status(running), ScanJob.Status.RUNNING)
        self.assertEqual(status(queued), ScanJob.Status.PENDING)
        self.assertEqual(status(done), ScanJob.Status.SUCCESS)


class AuthFlowTests(TestCase):
    PASSWORD = "correct horse battery staple"

    def setUp(self):
        cache.clear()  # throttle counters live in the cache
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user("erin", password=self.PASSWORD)

    def login(self, password=None, **headers):
        return self.client.post(
            "/api/auth/login/", data={"username": "erin", "password": password or self.PASSWORD},
            content_type=JSON, **headers,
        )

    def test_login_logout_and_audit_trail(self):
        tokens = self.login().json()
        self.assertIn("access", tokens)

        auth = {"HTTP_AUTHORIZATION": f"Bearer {tokens['access']}"}
        response = self.client.post(
            "/api/auth/logout/", data={"refresh": tokens["refresh"]}, content_type=JSON, **auth
        )
        self.assertEqual(response.status_code, 204)

        # The blacklisted refresh token can't mint new access tokens.
        refresh = self.client.post(
            "/api/token/refresh/", data={"refresh": tokens["refresh"]}, content_type=JSON
        )
        self.assertEqual(refresh.status_code, 401)

        events = list(AuthEvent.objects.order_by("created_at").values_list("event_type", flat=True))
        self.assertEqual(events, ["login_success", "logout"])

    def test_failed_login_is_audited(self):
        self.assertEqual(self.login("wrong").status_code, 401)
        event = AuthEvent.objects.get()
        self.assertEqual(event.event_type, AuthEvent.EventType.LOGIN_FAILED)
        self.assertEqual(event.attempted_username, "erin")

    def test_change_password_revokes_other_sessions(self):
        other_session = self.login().json()
        current = self.login().json()
        auth = {"HTTP_AUTHORIZATION": f"Bearer {current['access']}"}

        wrong = self.client.post(
            "/api/auth/change-password/",
            data={"current_password": "nope", "new_password": "a brand new passphrase 42"},
            content_type=JSON, **auth,
        )
        self.assertEqual(wrong.status_code, 400)

        changed = self.client.post(
            "/api/auth/change-password/",
            data={"current_password": self.PASSWORD, "new_password": "a brand new passphrase 42"},
            content_type=JSON, **auth,
        )
        self.assertEqual(changed.status_code, 200)

        refresh = self.client.post(
            "/api/token/refresh/", data={"refresh": other_session["refresh"]}, content_type=JSON
        )
        self.assertEqual(refresh.status_code, 401)

    def test_login_is_throttled(self):
        statuses = [self.login("wrong").status_code for _ in range(6)]
        self.assertEqual(statuses, [401] * 5 + [429])

    @override_settings(NUM_PROXIES=0)
    def test_throttle_cannot_be_dodged_with_a_forged_forwarded_header(self):
        statuses = [
            self.login("wrong", HTTP_X_FORWARDED_FOR=f"198.51.100.{i}").status_code for i in range(6)
        ]
        self.assertEqual(statuses[-1], 429)


class ClientIpTests(SimpleTestCase):
    def request(self, forwarded_for=None):
        extra = {"HTTP_X_FORWARDED_FOR": forwarded_for} if forwarded_for else {}
        return RequestFactory().get("/", REMOTE_ADDR="203.0.113.9", **extra)

    @override_settings(NUM_PROXIES=0)
    def test_forwarded_header_is_ignored_without_trusted_proxies(self):
        self.assertEqual(get_client_ip(self.request("1.2.3.4")), "203.0.113.9")

    @override_settings(NUM_PROXIES=1)
    def test_one_proxy_trusts_only_the_last_hop(self):
        # "6.6.6.6" was supplied by the client; the proxy appended what it saw.
        self.assertEqual(get_client_ip(self.request("6.6.6.6, 198.51.100.7")), "198.51.100.7")

    @override_settings(NUM_PROXIES=1)
    def test_falls_back_to_remote_addr_when_header_is_missing(self):
        self.assertEqual(get_client_ip(self.request()), "203.0.113.9")


class MetricsEndpointTests(SimpleTestCase):
    @override_settings(DEBUG=False, METRICS_TOKEN="")
    def test_hidden_in_production_without_a_token(self):
        self.assertEqual(self.client.get("/metrics").status_code, 404)

    @override_settings(DEBUG=False, METRICS_TOKEN="s3cret")
    def test_requires_the_bearer_token(self):
        self.assertEqual(self.client.get("/metrics").status_code, 401)
        self.assertEqual(
            self.client.get("/metrics", HTTP_AUTHORIZATION="Bearer wrong").status_code, 401
        )
        self.assertEqual(
            self.client.get("/metrics", HTTP_AUTHORIZATION="Bearer s3cret").status_code, 200
        )

    @override_settings(DEBUG=True, METRICS_TOKEN="")
    def test_open_in_debug(self):
        self.assertEqual(self.client.get("/metrics").status_code, 200)


class MemberManagementTests(OrgTestCase):
    def members_url(self, membership=None):
        base = f"/api/organizations/{self.org.id}/members/"
        return f"{base}{membership.id}/" if membership else base

    def membership(self, role):
        return Membership.objects.get(organization=self.org, user=self.users[role])

    def add(self, identifier, role="viewer"):
        return self.client.post(
            self.members_url(), data={"identifier": identifier, "role": role}, content_type=JSON
        )

    def test_any_member_can_list_members_but_outsiders_cannot(self):
        self.login("viewer")
        response = self.client.get(self.members_url())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {m["username"]: m["role"] for m in response.json()},
            {"owner": "owner", "admin": "admin", "analyst": "analyst", "viewer": "viewer"},
        )
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(self.members_url()).status_code, 404)

    def test_admin_can_add_an_existing_user_by_username_or_email(self):
        self.outsider.email = "Out@Example.com"
        self.outsider.save()
        self.login("admin")
        response = self.add("out@example.com", "analyst")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["username"], "outsider")
        self.assertEqual(
            Membership.objects.get(user=self.outsider, organization=self.org).role, "analyst"
        )

    def test_adding_is_refused_for_non_admins_unknown_users_and_duplicates(self):
        self.login("analyst")
        self.assertEqual(self.add("outsider").status_code, 403)
        self.login("admin")
        self.assertEqual(self.add("nobody-by-this-name").status_code, 400)
        self.assertEqual(self.add("viewer").status_code, 400)

    def test_only_an_owner_can_hand_out_or_touch_the_owner_role(self):
        self.login("admin")
        self.assertEqual(self.add("outsider", "owner").status_code, 403)
        promote = self.client.patch(
            self.members_url(self.membership("viewer")), data={"role": "owner"}, content_type=JSON
        )
        self.assertEqual(promote.status_code, 403)
        demote_owner = self.client.patch(
            self.members_url(self.membership("owner")), data={"role": "viewer"}, content_type=JSON
        )
        self.assertEqual(demote_owner.status_code, 403)
        self.assertEqual(
            self.client.delete(self.members_url(self.membership("owner"))).status_code, 403
        )

        self.login("owner")
        self.assertEqual(self.add("outsider", "owner").status_code, 201)

    def test_admin_can_change_roles_and_remove_members(self):
        self.login("admin")
        changed = self.client.patch(
            self.members_url(self.membership("viewer")), data={"role": "analyst"}, content_type=JSON
        )
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(self.membership("viewer").role, "analyst")

        self.assertEqual(
            self.client.delete(self.members_url(self.membership("analyst"))).status_code, 204
        )
        self.assertFalse(
            Membership.objects.filter(organization=self.org, user=self.users["analyst"]).exists()
        )

    def test_the_last_owner_cannot_leave_or_be_demoted(self):
        self.login("owner")
        own = self.membership("owner")
        self.assertEqual(self.client.delete(self.members_url(own)).status_code, 400)
        self.assertEqual(
            self.client.patch(self.members_url(own), data={"role": "admin"}, content_type=JSON).status_code,
            400,
        )
        self.assertEqual(self.membership("owner").role, "owner")

        # With a second owner in place, stepping down is fine.
        self.add("outsider", "owner")
        self.assertEqual(
            self.client.patch(self.members_url(own), data={"role": "admin"}, content_type=JSON).status_code,
            200,
        )

    def test_anyone_can_leave_but_not_remove_others(self):
        self.login("viewer")
        self.assertEqual(
            self.client.delete(self.members_url(self.membership("analyst"))).status_code, 403
        )
        self.assertEqual(
            self.client.delete(self.members_url(self.membership("viewer"))).status_code, 204
        )

    def test_membership_id_from_another_org_404s(self):
        other_org = Organization.objects.create(name="Other", root_domain="other.com")
        foreign = Membership.objects.create(
            user=self.outsider, organization=other_org, role=Membership.Role.VIEWER
        )
        self.login("owner")
        self.assertEqual(self.client.delete(self.members_url(foreign)).status_code, 404)
        self.assertTrue(Membership.objects.filter(id=foreign.id).exists())


class ScannerListTests(OrgTestCase):
    def test_every_scanner_has_a_label_and_description(self):
        self.login("viewer")
        scanners = self.client.get("/api/scanners/").json()
        self.assertGreaterEqual(len(scanners), 7)
        for scanner in scanners:
            with self.subTest(scanner=scanner["name"]):
                self.assertTrue(scanner["label"])
                self.assertNotEqual(scanner["label"], scanner["name"])
                self.assertTrue(scanner["description"])


class FindingListOrderAndKindTests(OrgTestCase):
    def setUp(self):
        super().setUp()
        self.login("viewer")
        make_finding(self.asset, title="info port", severity=Finding.Severity.INFO)
        make_finding(self.asset, title="critical vuln", severity=Finding.Severity.CRITICAL,
                     finding_type=Finding.FindingType.NUCLEI_MATCH)
        make_finding(self.asset, title="medium header", severity=Finding.Severity.MEDIUM,
                     finding_type=Finding.FindingType.MISSING_HEADER)
        # Created last, so newest -- and must still not come first.
        make_finding(self.asset, title="dns record", severity=Finding.Severity.INFO,
                     finding_type=Finding.FindingType.DNS_CHANGE)
        make_finding(self.asset, title="screenshot", severity=Finding.Severity.INFO,
                     finding_type=Finding.FindingType.SCREENSHOT)

    def titles(self, query=""):
        return [f["title"] for f in self.client.get(f"/api/findings/{query}").json()["results"]]

    def test_worst_severity_comes_first(self):
        self.assertEqual(self.titles()[:2], ["critical vuln", "medium header"])

    def test_kind_separates_issues_from_inventory(self):
        self.assertEqual(self.titles("?kind=issue"), ["critical vuln", "medium header", "info port"])
        self.assertCountEqual(self.titles("?kind=inventory"), ["dns record", "screenshot"])

    def test_export_is_ordered_worst_first(self):
        response = self.client.get(f"/api/organizations/{self.org.id}/export/?export_format=json")
        self.assertEqual(response.json()[0]["title"], "critical vuln")


class RiskSummaryTests(OrgTestCase):
    def setUp(self):
        super().setUp()
        self.login("viewer")
        self.clean = [
            Asset.objects.create(organization=self.org, value=f"clean{i}.acme.com", asset_type="subdomain")
            for i in range(20)
        ]
        self.exposed = Asset.objects.create(organization=self.org, value="db.acme.com", asset_type="subdomain")
        make_finding(self.exposed, title="rdp", severity=Finding.Severity.HIGH)
        make_finding(self.exposed, title="vuln", severity=Finding.Severity.CRITICAL,
                     finding_type=Finding.FindingType.NUCLEI_MATCH)

    def summary(self):
        return self.client.get(f"/api/organizations/{self.org.id}/risk-summary/").json()

    def test_clean_assets_do_not_dilute_the_grade(self):
        summary = self.summary()
        self.assertEqual(summary["asset_count"], 22)
        self.assertEqual(summary["assets_at_risk"], 1)
        # 100 - 15 (high) - 25 (critical); not averaged with 21 perfect scores.
        self.assertEqual(summary["average_risk_score"], 60)
        self.assertEqual(summary["average_risk_grade"], "C")
        self.assertEqual(summary["grade_distribution"], {"C": 1, "A+": 21})

    def test_worst_assets_are_listed_lowest_score_first(self):
        other = Asset.objects.create(organization=self.org, value="www.acme.com", asset_type="subdomain")
        make_finding(other, title="header", severity=Finding.Severity.LOW,
                     finding_type=Finding.FindingType.MISSING_HEADER)
        worst = self.summary()["worst_assets"]
        self.assertEqual([a["value"] for a in worst], ["db.acme.com", "www.acme.com"])
        self.assertEqual(worst[0]["open_findings"], 2)
        self.assertEqual(worst[0]["risk_grade"], "C")

    def test_inventory_findings_do_not_affect_risk(self):
        for i in range(30):
            make_finding(self.clean[0], title=f"dns {i}", severity=Finding.Severity.INFO,
                         finding_type=Finding.FindingType.DNS_CHANGE)
        self.assertEqual(Asset.objects.get(id=self.clean[0].id).risk_score, 100)
        summary = self.summary()
        self.assertEqual(summary["assets_at_risk"], 1)
        self.assertEqual(summary["active_findings_by_severity"]["info"], 0)

    def test_no_issues_is_a_perfect_score_and_no_assets_is_none(self):
        Finding.objects.all().delete()
        self.assertEqual(self.summary()["average_risk_score"], 100)
        Asset.objects.filter(organization=self.org).delete()
        summary = self.summary()
        self.assertIsNone(summary["average_risk_score"])
        self.assertIsNone(summary["average_risk_grade"])

    def test_cost_does_not_grow_with_asset_count(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        # The first call of the day inserts today's trend point; later ones
        # update it. Compare like with like.
        self.summary()
        with CaptureQueriesContext(connection) as before:
            self.summary()
        for i in range(30):
            asset = Asset.objects.create(organization=self.org, value=f"more{i}.acme.com", asset_type="subdomain")
            make_finding(asset, title=f"issue {i}", severity=Finding.Severity.LOW,
                         finding_type=Finding.FindingType.MISSING_HEADER)
        with CaptureQueriesContext(connection) as after:
            self.summary()
        self.assertEqual(len(after), len(before))


@override_settings(REQUIRE_DOMAIN_VERIFICATION=False)
class DomainScanTests(OrgTestCase):
    """'Run scan' for a whole organization: no asset is chosen."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        for i in range(4):
            Asset.objects.create(organization=self.org, value=f"h{i}.acme.com", asset_type="subdomain")
        Asset.objects.create(
            organization=self.org, value="gone.acme.com", asset_type="subdomain", is_active=False
        )
        self.login("analyst")

    def start(self, scanner_name="nmap"):
        return self.client.post(
            "/api/scan-jobs/trigger/",
            data={"scanner_name": scanner_name, "organization_id": str(self.org.id)},
            content_type=JSON,
        )

    def progress(self):
        response = self.client.get(f"/api/scan-jobs/progress/?organization={self.org.id}")
        self.assertEqual(response.status_code, 200)
        return {row["scanner_name"]: row for row in response.json()}

    def test_asset_level_scanner_runs_on_every_active_asset(self):
        with patch("apps.api.views.fan_out_domain_scan.delay") as fan_out:
            response = self.start("nmap")
        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["target_count"], 5)  # root domain + 4 hosts, not the inactive one
        # The last argument is who started it, recorded on every scan of the run.
        fan_out.assert_called_once_with(str(self.org.id), "nmap", body["batch_id"], fan_out.call_args.args[3])
        self.assertIsNotNone(fan_out.call_args.args[3])

        with patch("apps.scanning.tasks.run_scan_job.delay") as run:
            fan_out_domain_scan(str(self.org.id), "nmap", body["batch_id"])

        jobs = ScanJob.objects.filter(batch_id=body["batch_id"])
        self.assertEqual(jobs.count(), 5)
        self.assertEqual(run.call_count, 5)
        self.assertFalse(jobs.filter(asset__value="gone.acme.com").exists())
        self.assertEqual(set(jobs.values_list("scanner_name", flat=True)), {"nmap"})

    def test_a_deliberate_run_scans_assets_the_daily_schedule_already_did_today(self):
        with patch("apps.scanning.tasks.run_scan_job.delay"):
            trigger_daily_scans()
            before = ScanJob.objects.filter(scanner_name="nmap").count()
            fan_out_domain_scan(str(self.org.id), "nmap", "0b0f6c1e-0000-4000-8000-000000000001")
        self.assertEqual(ScanJob.objects.filter(scanner_name="nmap").count(), before + 5)

    def test_organization_level_scanner_starts_a_single_job(self):
        with patch("apps.api.views.run_scan_job.delay") as run:
            response = self.start("subfinder")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["target_count"], 1)
        job = ScanJob.objects.get(batch_id=response.json()["batch_id"])
        self.assertIsNone(job.asset)
        run.assert_called_once_with(str(job.id))

    def test_second_click_is_refused_until_the_run_finishes(self):
        with patch("apps.api.views.fan_out_domain_scan.delay"):
            first = self.start("nmap")
            # Fan-out hasn't written any job yet: the lock is what refuses this.
            self.assertEqual(self.start("nmap").status_code, 409)
            # A different scanner is independent.
            self.assertEqual(self.start("httpx").status_code, 202)

        with patch("apps.scanning.tasks.run_scan_job.delay"):
            fan_out_domain_scan(str(self.org.id), "nmap", first.json()["batch_id"])
        with patch("apps.api.views.fan_out_domain_scan.delay"):
            # Lock released, but the jobs are still pending.
            self.assertEqual(self.start("nmap").status_code, 409)
            ScanJob.objects.filter(batch_id=first.json()["batch_id"]).update(status=ScanJob.Status.SUCCESS)
            self.assertEqual(self.start("nmap").status_code, 202)

    def test_progress_reports_the_latest_run_per_scanner(self):
        self.assertEqual(self.progress(), {})

        old_batch, new_batch = "0b0f6c1e-0000-4000-8000-00000000000a", "0b0f6c1e-0000-4000-8000-00000000000b"
        with patch("apps.scanning.tasks.run_scan_job.delay"):
            fan_out_domain_scan(str(self.org.id), "nmap", old_batch)
            ScanJob.objects.filter(batch_id=old_batch).update(
                status=ScanJob.Status.SUCCESS, created_at=timezone.now() - timedelta(hours=5)
            )
            fan_out_domain_scan(str(self.org.id), "nmap", new_batch)

        jobs = list(ScanJob.objects.filter(batch_id=new_batch).order_by("asset__value"))
        ScanJob.objects.filter(id=jobs[0].id).update(status=ScanJob.Status.SUCCESS)
        ScanJob.objects.filter(id=jobs[1].id).update(status=ScanJob.Status.FAILED)
        ScanJob.objects.filter(id=jobs[2].id).update(status=ScanJob.Status.RETRYING)

        nmap = self.progress()["nmap"]
        self.assertEqual(nmap["batch_id"], new_batch)
        self.assertEqual(
            {k: nmap[k] for k in ("total", "pending", "running", "success", "failed", "finished")},
            {"total": 5, "pending": 2, "running": 1, "success": 1, "failed": 1, "finished": False},
        )

        ScanJob.objects.filter(batch_id=new_batch).update(status=ScanJob.Status.SUCCESS)
        self.assertTrue(self.progress()["nmap"]["finished"])

    def test_progress_ignores_single_asset_scans_and_other_orgs(self):
        with patch("apps.api.views.run_scan_job.delay"):
            self.client.post(
                "/api/scan-jobs/trigger/",
                data={"scanner_name": "nmap", "asset_id": str(self.asset.id)}, content_type=JSON,
            )
        self.assertEqual(self.progress(), {})

        self.client.force_login(self.outsider)
        response = self.client.get(f"/api/scan-jobs/progress/?organization={self.org.id}")
        self.assertEqual(response.json(), [])
        self.assertEqual(self.client.get("/api/scan-jobs/progress/").status_code, 400)

    def test_viewer_cannot_start_a_domain_scan(self):
        self.login("viewer")
        with patch("apps.api.views.fan_out_domain_scan.delay") as fan_out:
            self.assertEqual(self.start("nmap").status_code, 403)
        fan_out.assert_not_called()

    @override_settings(REQUIRE_DOMAIN_VERIFICATION=True)
    def test_unverified_domain_cannot_be_scanned(self):
        with patch("apps.api.views.fan_out_domain_scan.delay") as fan_out:
            self.assertEqual(self.start("nmap").status_code, 403)
        fan_out.assert_not_called()


class GuidanceTests(SimpleTestCase):
    def guide(self, finding_type, raw_data):
        from types import SimpleNamespace

        from apps.findings.guidance import guidance_for

        return guidance_for(SimpleNamespace(finding_type=finding_type, raw_data=raw_data))

    def test_exposed_remote_desktop_is_explained_in_business_terms(self):
        guidance = self.guide(Finding.FindingType.OPEN_PORT, {"port": "3389"})
        self.assertIn("ransomware", guidance["impact"])
        self.assertIn("VPN", guidance["remediation"])

    def test_a_public_web_port_is_not_dressed_up_as_a_problem(self):
        guidance = self.guide(Finding.FindingType.OPEN_PORT, {"port": "443"})
        self.assertIn("expected for a website", guidance["impact"])

    def test_unknown_ports_and_headers_still_get_guidance(self):
        self.assertTrue(self.guide(Finding.FindingType.OPEN_PORT, {"port": "31337"})["remediation"])
        self.assertTrue(self.guide(Finding.FindingType.MISSING_HEADER, {"header": "X-New"})["remediation"])

    def test_missing_header_says_what_to_send(self):
        guidance = self.guide(Finding.FindingType.MISSING_HEADER, {"header": "Strict-Transport-Security"})
        self.assertIn("max-age", guidance["remediation"])

    def test_expired_certificate_is_more_urgent_than_an_expiring_one(self):
        expired = self.guide(Finding.FindingType.EXPIRED_SSL, {"days_remaining": -3})
        expiring = self.guide(Finding.FindingType.EXPIRED_SSL, {"days_remaining": 20})
        self.assertIn("has expired", expired["impact"])
        self.assertIn("before it expires", expiring["remediation"])

    def test_inventory_findings_have_no_guidance(self):
        for kind in Finding.INVENTORY_TYPES:
            self.assertEqual(self.guide(kind, {}), {"impact": "", "remediation": ""})


class ChangesAndReportTests(OrgTestCase):
    def setUp(self):
        super().setUp()
        self.login("viewer")
        long_ago = timezone.now() - timedelta(days=30)

        Asset.objects.filter(id=self.asset.id).update(first_seen=long_ago)
        self.new_host = Asset.objects.create(organization=self.org, value="new.acme.com", asset_type="subdomain")

        old = make_finding(self.asset, title="old open issue")
        Finding.objects.filter(id=old.id).update(first_seen=long_ago)
        self.fresh = make_finding(self.new_host, title="rdp exposed", severity=Finding.Severity.CRITICAL,
                                  raw_data={"port": "3389"})
        fixed = make_finding(self.asset, title="fixed this week", is_active=False,
                             resolved_at=timezone.now() - timedelta(days=2))
        Finding.objects.filter(id=fixed.id).update(first_seen=long_ago)
        fixed_long_ago = make_finding(self.asset, title="fixed last month", is_active=False,
                                      resolved_at=long_ago)
        Finding.objects.filter(id=fixed_long_ago.id).update(first_seen=long_ago)
        # Inventory never counts as a change in issues.
        make_finding(self.new_host, title="dns", severity=Finding.Severity.INFO,
                     finding_type=Finding.FindingType.DNS_CHANGE)

    def changes(self, query=""):
        return self.client.get(f"/api/organizations/{self.org.id}/changes/{query}").json()

    def test_reports_what_appeared_and_what_went_away_this_week(self):
        changes = self.changes()
        self.assertEqual(changes["days"], 7)
        self.assertEqual(changes["new_assets"]["count"], 1)
        self.assertEqual(changes["new_assets"]["items"][0]["value"], "new.acme.com")
        self.assertEqual([i["title"] for i in changes["new_issues"]["items"]], ["rdp exposed"])
        self.assertEqual(changes["new_issues"]["by_severity"]["critical"], 1)
        self.assertEqual([i["title"] for i in changes["resolved_issues"]["items"]], ["fixed this week"])

    def test_window_is_adjustable_and_clamped(self):
        self.assertEqual(self.changes("?days=60")["resolved_issues"]["count"], 2)
        self.assertEqual(self.changes("?days=9999")["days"], 90)
        self.assertEqual(self.changes("?days=abc")["days"], 7)

    def test_a_scan_stamps_resolution_and_clears_it_if_the_issue_returns(self):
        key = Finding.build_dedupe_key(Finding.FindingType.OPEN_PORT, "3389/tcp")
        Finding.objects.filter(id=self.fresh.id).update(dedupe_key=key)
        results = []

        class Scanner:
            name = "fake"
            applies_to = "asset"
            owned_finding_types = [Finding.FindingType.OPEN_PORT]

            def run(self, target):
                return results

            def extract_technologies(self, target):
                return []

        def scan(job_key):
            job = ScanJob.objects.create(
                organization=self.org, asset=self.new_host, scanner_name="fake", idempotency_key=job_key
            )
            with patch("apps.scanning.tasks.get_scanner", return_value=Scanner), patch(
                "apps.scanning.tasks.assert_public_target"
            ):
                run_scan_job.apply(args=[str(job.id)])
            self.fresh.refresh_from_db()

        scan("gone")
        self.assertFalse(self.fresh.is_active)
        self.assertIsNotNone(self.fresh.resolved_at)

        results.append(RawFinding(
            finding_type=Finding.FindingType.OPEN_PORT, identifier="3389/tcp",
            severity=Finding.Severity.HIGH, title="rdp exposed",
        ))
        scan("back")
        self.assertTrue(self.fresh.is_active)
        self.assertIsNone(self.fresh.resolved_at)

    def test_findings_carry_plain_language_guidance(self):
        finding = self.client.get(f"/api/findings/{self.fresh.id}/").json()
        self.assertIn("ransomware", finding["impact"])
        self.assertTrue(finding["remediation"])

    def test_report_is_a_pdf_and_only_for_members(self):
        response = self.client.get(f"/api/organizations/{self.org.id}/report/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertIn("acme.com-report-", response["Content-Disposition"])
        self.assertTrue(response.content.startswith(b"%PDF"))

        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(f"/api/organizations/{self.org.id}/report/").status_code, 404)
        self.assertEqual(self.client.get(f"/api/organizations/{self.org.id}/changes/").status_code, 404)

    def test_report_handles_an_empty_organization_and_markup_in_titles(self):
        make_finding(self.asset, title="<script>alert(1)</script> & co", severity=Finding.Severity.HIGH)
        self.assertEqual(self.client.get(f"/api/organizations/{self.org.id}/report/").status_code, 200)

        self.login("owner")
        empty = self.client.post(
            "/api/organizations/", data={"name": "Empty", "root_domain": "empty-example.com"}, content_type=JSON
        ).json()
        Asset.objects.filter(organization_id=empty["id"]).delete()
        self.assertEqual(self.client.get(f"/api/organizations/{empty['id']}/report/").status_code, 200)


class WebhookRuleTests(OrgTestCase):
    HOOK = "https://hooks.example.com/services/T000/B000/abc"

    def setUp(self):
        super().setUp()
        self.login("admin")
        self.public = patch("apps.notifications.serializers.assert_public_target")
        self.public.start()
        self.addCleanup(self.public.stop)

    def create(self, **fields):
        return self.client.post(
            "/api/notification-rules/", data={"organization": str(self.org.id), **fields}, content_type=JSON
        )

    def test_webhook_rule_needs_a_public_https_address(self):
        self.assertEqual(self.create(channel="webhook").status_code, 400)
        self.assertEqual(self.create(channel="webhook", webhook_url="http://hooks.example.com/x").status_code, 400)

        self.public.stop()
        with patch("apps.scanning.targets.socket.getaddrinfo",
                   return_value=[(None, None, None, "", ("10.0.0.5", 0))]):
            internal = self.create(channel="webhook", webhook_url="https://internal.example.com/hook")
        self.public.start()
        self.assertEqual(internal.status_code, 400)
        self.assertIn("public", internal.json()["webhook_url"][0])

        created = self.create(channel="webhook", webhook_url=self.HOOK, min_severity="high")
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["recipient_email"], "")

    def test_email_rule_still_works_and_needs_an_address(self):
        self.assertEqual(self.create(recipient_email="sec@acme.com").status_code, 201)
        self.assertEqual(self.create(channel="email").status_code, 400)

    def test_same_destination_twice_is_refused_but_several_webhooks_are_fine(self):
        self.assertEqual(self.create(channel="webhook", webhook_url=self.HOOK).status_code, 201)
        duplicate = self.create(channel="webhook", webhook_url=self.HOOK)
        self.assertEqual(duplicate.status_code, 400)
        self.assertIn("already a rule", duplicate.json()["non_field_errors"][0])
        self.assertEqual(self.create(channel="webhook", webhook_url=self.HOOK + "2").status_code, 201)


class WebhookDeliveryTests(OrgTestCase):
    HOOK = "https://hooks.example.com/services/T000/B000/abc"

    def setUp(self):
        super().setUp()
        from apps.notifications.models import NotificationRule as Rule

        self.finding = make_finding(self.asset, title="rdp exposed", severity=Finding.Severity.CRITICAL)
        Rule.objects.create(organization=self.org, channel="webhook", webhook_url=self.HOOK, min_severity="low")
        Rule.objects.create(organization=self.org, recipient_email="sec@acme.com", min_severity="low")

    def notify(self):
        from apps.notifications.tasks import notify_new_findings

        return notify_new_findings("job", [str(self.finding.id)])

    def test_posts_a_chat_message_and_sends_the_email(self):
        import json as json_module

        from django.core import mail

        with patch("apps.notifications.tasks.assert_public_target"), patch(
            "apps.notifications.tasks.urllib.request.OpenerDirector.open"
        ) as opened:
            result = self.notify()

        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, self.HOOK)
        self.assertEqual(request.get_method(), "POST")
        text = json_module.loads(request.data)["text"]
        self.assertIn("1 new security issue on Acme", text)
        self.assertIn("[CRITICAL] rdp exposed (acme.com)", text)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Sent 2 notification(s)", result)

    def test_a_failing_webhook_does_not_stop_the_email(self):
        import urllib.error

        from django.core import mail

        with patch("apps.notifications.tasks.assert_public_target"), patch(
            "apps.notifications.tasks.urllib.request.OpenerDirector.open",
            side_effect=urllib.error.URLError("down"),
        ):
            result = self.notify()
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Sent 1 notification(s)", result)

    def test_webhook_that_now_points_inward_is_not_called(self):
        with patch(
            "apps.notifications.tasks.assert_public_target", side_effect=TargetNotAllowed("private")
        ), patch("apps.notifications.tasks.urllib.request.OpenerDirector.open") as opened:
            self.notify()
        opened.assert_not_called()

    def test_redirects_are_not_followed(self):
        from apps.notifications.tasks import _NoRedirects

        self.assertIsNone(_NoRedirects().redirect_request(None, None, 302, "Found", {}, "http://10.0.0.1/"))


class OrganizationDeletionTests(OrgTestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.media_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media_root)
        settings_override = override_settings(MEDIA_ROOT=self.media_root)
        settings_override.enable()
        self.addCleanup(settings_override.disable)

        # Everything an organization can own.
        from apps.assets.models import Technology

        self.job = ScanJob.objects.create(
            organization=self.org, asset=self.asset, scanner_name="nmap", idempotency_key="org-del"
        )
        make_finding(self.asset, scan_job=self.job)
        Technology.objects.create(asset=self.asset, name="nginx")
        NotificationRule.objects.create(organization=self.org, recipient_email="sec@acme.com")
        self.shots = Path(self.media_root) / "screenshots" / str(self.asset.id)
        self.shots.mkdir(parents=True)
        (self.shots / "a.png").write_bytes(b"png")

        # And a neighbour that must come through untouched.
        self.other = Organization.objects.create(name="Other", root_domain="other.com")
        self.other_asset = Asset.objects.create(organization=self.other, value="other.com", asset_type="domain")
        make_finding(self.other_asset, title="neighbour finding")
        ScanJob.objects.create(
            organization=self.other, asset=self.other_asset, scanner_name="nmap", idempotency_key="other"
        )
        self.other_shots = Path(self.media_root) / "screenshots" / str(self.other_asset.id)
        self.other_shots.mkdir(parents=True)

    def delete(self):
        return self.client.delete(f"/api/organizations/{self.org.id}/")

    def test_owner_delete_removes_the_organization_and_everything_under_it(self):
        from apps.assets.models import Technology

        self.login("owner")
        self.assertEqual(self.delete().status_code, 204)

        self.assertFalse(Organization.objects.filter(id=self.org.id).exists())
        self.assertEqual(Asset.objects.filter(organization_id=self.org.id).count(), 0)
        self.assertEqual(ScanJob.objects.filter(organization_id=self.org.id).count(), 0)
        self.assertEqual(Membership.objects.filter(organization_id=self.org.id).count(), 0)
        self.assertEqual(NotificationRule.objects.filter(organization_id=self.org.id).count(), 0)
        self.assertEqual(Technology.objects.count(), 0)
        self.assertFalse(self.shots.exists())
        # The people are not deleted, only their membership.
        self.assertTrue(User.objects.filter(username="viewer").exists())

    def test_other_organizations_are_untouched(self):
        self.login("owner")
        self.delete()
        self.assertTrue(Organization.objects.filter(id=self.other.id).exists())
        self.assertEqual(Finding.objects.count(), 1)
        self.assertEqual(Finding.objects.get().title, "neighbour finding")
        self.assertEqual(ScanJob.objects.count(), 1)
        self.assertTrue(self.other_shots.exists())

    def test_only_the_owner_can_delete_and_a_refusal_removes_nothing(self):
        self.login("admin")
        self.assertEqual(self.delete().status_code, 403)
        self.assertTrue(Organization.objects.filter(id=self.org.id).exists())
        self.assertEqual(Finding.objects.count(), 2)
        self.assertTrue(self.shots.exists())

    def test_a_scan_still_queued_for_a_deleted_organization_ends_quietly(self):
        job_id = str(self.job.id)
        self.login("owner")
        self.delete()
        result = run_scan_job.apply(args=[job_id])
        self.assertTrue(result.successful())
        self.assertIsNone(result.result)

    def test_the_domain_can_be_registered_again_afterwards(self):
        self.login("owner")
        self.delete()
        again = self.client.post(
            "/api/organizations/", data={"name": "Acme again", "root_domain": "acme.com"}, content_type=JSON
        )
        self.assertEqual(again.status_code, 201)



class RemediationWorkflowTests(OrgTestCase):
    def setUp(self):
        super().setUp()
        self.finding = make_finding(self.asset, title="rdp", severity=Finding.Severity.HIGH)

    def assign(self, assignee):
        return self.client.post(
            f"/api/findings/{self.finding.id}/assign/", data={"assignee": assignee}, content_type=JSON
        )

    def test_analyst_assigns_a_member_and_it_is_logged(self):
        from apps.audit_logs.models import ActivityEvent

        self.login("analyst")
        response = self.assign(self.users["admin"].id)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["assignee_username"], "admin")
        event = ActivityEvent.objects.get(verb="finding_assigned")
        self.assertEqual(event.actor_name, "analyst")
        self.assertIn("to admin", event.summary)

        self.assertEqual(self.assign(None).json()["assignee"], None)

    def test_assignment_rules(self):
        self.login("viewer")
        self.assertEqual(self.assign(self.users["admin"].id).status_code, 403)
        self.login("analyst")
        self.assertEqual(self.assign(self.outsider.id).status_code, 400)

    def test_fix_by_date_and_overdue_follow_the_sla(self):
        from datetime import timedelta as td

        self.login("viewer")
        body = self.client.get(f"/api/findings/{self.finding.id}/").json()
        self.assertFalse(body["overdue"])
        self.assertIsNotNone(body["due_at"])

        Finding.objects.filter(id=self.finding.id).update(first_seen=timezone.now() - td(days=31))
        body = self.client.get(f"/api/findings/{self.finding.id}/").json()
        self.assertTrue(body["overdue"])
        self.assertEqual([f["id"] for f in self.client.get("/api/findings/?overdue=true").json()["results"]],
                         [str(self.finding.id)])

        # Triaged findings are never overdue.
        Finding.objects.filter(id=self.finding.id).update(status=Finding.Status.ACCEPTED)
        self.assertEqual(self.client.get("/api/findings/?overdue=true").json()["count"], 0)

    def test_assignee_filters(self):
        other = make_finding(self.asset, title="other")
        Finding.objects.filter(id=self.finding.id).update(assignee=self.users["analyst"])
        self.login("analyst")
        mine = self.client.get("/api/findings/?assignee=me").json()["results"]
        nobody = self.client.get("/api/findings/?assignee=none").json()["results"]
        self.assertEqual([f["id"] for f in mine], [str(self.finding.id)])
        self.assertEqual([f["id"] for f in nobody], [str(other.id)])

    def test_dashboard_reports_remediation_figures(self):
        from datetime import timedelta as td

        fixed = make_finding(self.asset, title="fixed", is_active=False, resolved_at=timezone.now())
        Finding.objects.filter(id=fixed.id).update(first_seen=timezone.now() - td(days=10))
        Finding.objects.filter(id=self.finding.id).update(first_seen=timezone.now() - td(days=40))
        self.login("viewer")
        remediation = self.client.get(f"/api/organizations/{self.org.id}/risk-summary/").json()["remediation"]
        self.assertEqual(remediation["overdue"], 1)
        self.assertEqual(remediation["unassigned_critical_high"], 1)
        self.assertEqual(remediation["mean_days_to_fix"], 10.0)
        self.assertEqual(remediation["sla_days"]["critical"], 7)


class ComplianceTests(OrgTestCase):
    def test_issues_are_mapped_to_framework_controls(self):
        make_finding(self.asset, title="rdp", severity=Finding.Severity.HIGH)  # open port
        make_finding(self.asset, title="hsts", finding_type=Finding.FindingType.MISSING_HEADER,
                     severity=Finding.Severity.MEDIUM)
        make_finding(self.asset, title="tls", finding_type=Finding.FindingType.WEAK_TLS,
                     severity=Finding.Severity.MEDIUM, status=Finding.Status.ACCEPTED)
        self.login("viewer")
        body = self.client.get(f"/api/organizations/{self.org.id}/compliance/").json()
        self.assertIn("not a compliance assessment", body["disclaimer"])
        owasp = next(f for f in body["frameworks"] if f["id"] == "owasp")
        controls = {c["code"]: c["open_issues"] for c in owasp["controls"]}
        self.assertEqual(controls["A05"], 2)   # open port + missing header
        self.assertEqual(controls["A02"], 0)   # the TLS issue was accepted
        cis = next(f for f in body["frameworks"] if f["id"] == "cis")
        inventory = next(c for c in cis["controls"] if c["code"] == "1.1")
        self.assertFalse(inventory["inventory_only"])  # takeover issues map here too

    def test_findings_carry_their_controls_and_can_be_filtered_by_one(self):
        finding = make_finding(self.asset, title="rdp", severity=Finding.Severity.HIGH)
        make_finding(self.asset, title="tls", finding_type=Finding.FindingType.WEAK_TLS)
        self.login("viewer")
        body = self.client.get(f"/api/findings/{finding.id}/").json()
        self.assertIn("owasp:A05", [c["id"] for c in body["controls"]])
        filtered = self.client.get("/api/findings/?control=owasp:A05").json()["results"]
        self.assertEqual([f["title"] for f in filtered], ["rdp"])


class TrendAndNarrativeTests(OrgTestCase):
    def test_viewing_the_summary_records_todays_point_once(self):
        from apps.findings.models import RiskSnapshot

        self.login("viewer")
        make_finding(self.asset, title="rdp", severity=Finding.Severity.HIGH)
        self.client.get(f"/api/organizations/{self.org.id}/risk-summary/")
        self.client.get(f"/api/organizations/{self.org.id}/risk-summary/")
        self.assertEqual(RiskSnapshot.objects.filter(organization=self.org).count(), 1)
        points = self.client.get(f"/api/organizations/{self.org.id}/trend/").json()["points"]
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["critical_high"], 1)

    def test_narrative_describes_the_situation_and_the_trend(self):
        from datetime import date as d, timedelta as td

        from apps.findings.models import RiskSnapshot

        RiskSnapshot.objects.create(organization=self.org, date=d.today() - td(days=20), score=60, grade="C")
        make_finding(self.asset, title="rdp", severity=Finding.Severity.HIGH)
        self.login("viewer")
        narrative = " ".join(self.client.get(f"/api/organizations/{self.org.id}/risk-summary/").json()["narrative"])
        self.assertIn("1 of them has open issues", narrative)
        self.assertIn("graded B (84 out of 100)", narrative)
        self.assertIn("1 issue is critical or high", narrative)
        self.assertIn("improved by 24 points over the last 20 days", narrative)

    def test_daily_task_records_every_organization(self):
        from apps.findings.models import RiskSnapshot
        from apps.findings.tasks import record_risk_snapshots

        Organization.objects.create(name="Other", root_domain="other.com")
        record_risk_snapshots()
        self.assertEqual(RiskSnapshot.objects.count(), 2)


class ActivityLogTests(OrgTestCase):
    def test_members_see_who_did_what_newest_first(self):
        self.login("owner")
        self.client.post(f"/api/organizations/{self.org.id}/members/",
                         data={"identifier": "outsider", "role": "viewer"}, content_type=JSON)
        with patch("apps.api.views.has_verification_record", return_value=True):
            self.client.post(f"/api/organizations/{self.org.id}/verify-domain/")
        self.login("viewer")
        rows = self.client.get(f"/api/organizations/{self.org.id}/activity/").json()["results"]
        self.assertEqual([r["verb"] for r in rows], ["domain_verified", "member_added"])
        self.assertEqual(rows[1]["actor"], "owner")
        self.assertIn("outsider", rows[1]["summary"])

    def test_outsiders_cannot_read_it(self):
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(f"/api/organizations/{self.org.id}/activity/").status_code, 404)


class SurfaceMapTests(OrgTestCase):
    def test_risky_assets_first_then_clean_ones_up_to_the_limit(self):
        risky = Asset.objects.create(organization=self.org, value="db.acme.com", asset_type="subdomain")
        make_finding(risky, title="pg", severity=Finding.Severity.CRITICAL)
        Asset.objects.bulk_create(
            Asset(organization=self.org, value=f"h{i:03d}.acme.com", asset_type="subdomain") for i in range(80)
        )
        self.login("viewer")
        body = self.client.get(f"/api/organizations/{self.org.id}/surface-map/").json()
        self.assertEqual(body["root_domain"], "acme.com")
        self.assertEqual(body["total_assets"], 82)
        self.assertEqual(len(body["nodes"]), 60)
        self.assertEqual(body["hidden"], 22)
        self.assertEqual(body["nodes"][0]["value"], "db.acme.com")
        self.assertEqual(body["nodes"][0]["critical_high"], 1)
        self.assertFalse(body["nodes"][0]["clean"])
        self.assertTrue(body["nodes"][1]["clean"])


@override_settings(REQUIRE_DOMAIN_VERIFICATION=False)
class ManualAssetTests(OrgTestCase):
    def add(self, value):
        return self.client.post("/api/assets/", data={"organization": str(self.org.id), "value": value},
                                content_type=JSON)

    def test_analyst_adds_a_host_under_the_domain(self):
        self.login("analyst")
        response = self.add("VPN.acme.com.")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["value"], "vpn.acme.com")
        self.assertEqual(response.json()["source"], "manual")
        self.assertEqual(response.json()["risk_grade"], "A+")

    def test_hosts_outside_the_domain_and_duplicates_are_refused(self):
        self.login("analyst")
        for value in ["evil.com", "acme.com.evil.com", "notacme.com", "10.0.0.1", "localhost", "a b.acme.com"]:
            with self.subTest(value=value):
                self.assertEqual(self.add(value).status_code, 400)
        self.assertEqual(self.add("acme.com").status_code, 400)  # the root asset already exists
        self.assertIn("already being monitored", self.add("acme.com").json()["value"][0])

    def test_viewers_and_outsiders_cannot_add(self):
        self.login("viewer")
        self.assertEqual(self.add("x.acme.com").status_code, 403)
        self.client.force_login(self.outsider)
        self.assertEqual(self.add("x.acme.com").status_code, 403)


class WeeklyReportTests(OrgTestCase):
    def test_send_now_emails_the_pdf_with_the_summary(self):
        from django.core import mail

        make_finding(self.asset, title="rdp", severity=Finding.Severity.HIGH)
        rule = NotificationRule.objects.create(organization=self.org, recipient_email="ciso@acme.com")
        self.login("admin")
        with patch("apps.api.views.send_weekly_report.delay",
                   side_effect=lambda org, to: __import__("apps.notifications.tasks", fromlist=["x"]).send_weekly_report(org, to)):
            response = self.client.post(f"/api/notification-rules/{rule.id}/send-report/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ["ciso@acme.com"])
        self.assertIn("grade B", message.subject)
        self.assertIn("1 issue is critical or high", message.body)
        name, content, kind = message.attachments[0]
        self.assertEqual(kind, "application/pdf")
        self.assertTrue(content.startswith(b"%PDF"))

    def test_monday_job_sends_one_report_per_org_to_opted_in_emails(self):
        from apps.notifications.tasks import send_weekly_reports

        NotificationRule.objects.create(organization=self.org, recipient_email="a@acme.com", weekly_report=True)
        NotificationRule.objects.create(organization=self.org, recipient_email="b@acme.com", weekly_report=True)
        NotificationRule.objects.create(organization=self.org, recipient_email="c@acme.com")
        with patch("apps.notifications.tasks.send_weekly_report.delay") as send:
            send_weekly_reports()
        send.assert_called_once_with(str(self.org.id), ["a@acme.com", "b@acme.com"])

    def test_webhook_rules_never_get_the_report(self):
        self.login("admin")
        with patch("apps.notifications.serializers.assert_public_target"):
            response = self.client.post("/api/notification-rules/", data={
                "organization": str(self.org.id), "channel": "webhook",
                "webhook_url": "https://hooks.example.com/x", "weekly_report": True,
            }, content_type=JSON)
        self.assertFalse(response.json()["weekly_report"])
        rule = NotificationRule.objects.get()
        self.assertEqual(self.client.post(f"/api/notification-rules/{rule.id}/send-report/").status_code, 400)


class ScannerCategoryTests(OrgTestCase):
    def test_every_scanner_has_a_known_category(self):
        self.login("viewer")
        categories = {s["name"]: s["category"] for s in self.client.get("/api/scanners/").json()}
        self.assertEqual(len(categories), 25)
        self.assertEqual(set(categories.values()), {"discovery", "network", "web", "encryption", "email_domain"})



class GradeCapTests(OrgTestCase):
    def summary(self):
        self.login("viewer")
        return self.client.get(f"/api/organizations/{self.org.id}/risk-summary/").json()

    def test_many_tidy_hosts_cannot_hide_one_critical_issue(self):
        for i in range(20):
            asset = Asset.objects.create(organization=self.org, value=f"h{i}.acme.com", asset_type="subdomain")
            make_finding(asset, title=f"hdr {i}", severity=Finding.Severity.INFO,
                         finding_type=Finding.FindingType.MISSING_HEADER)
        make_finding(self.asset, title="db dump", severity=Finding.Severity.CRITICAL,
                     finding_type=Finding.FindingType.EXPOSED_FILE)
        summary = self.summary()
        self.assertEqual(summary["average_risk_grade"], "C")
        self.assertEqual(summary["average_risk_score"], 69)
        self.assertEqual(summary["grade_capped_by"], "critical")
        self.assertIn("critical issue holds the grade at C", " ".join(summary["narrative"]))

    def test_an_already_low_score_is_not_raised_by_the_cap(self):
        for title in ("a", "b", "c"):
            make_finding(self.asset, title=title, severity=Finding.Severity.CRITICAL)
        summary = self.summary()
        self.assertEqual(summary["average_risk_score"], 25)
        self.assertIsNone(summary["grade_capped_by"])

    def test_nothing_serious_open_means_no_cap(self):
        make_finding(self.asset, title="hdr", severity=Finding.Severity.LOW,
                     finding_type=Finding.FindingType.MISSING_HEADER)
        self.assertIsNone(self.summary()["grade_capped_by"])
