"""
Tests for the second round of product features: the fix plan and the
inventories, the finding workflow (comments, history, bulk actions,
time-limited acceptance, issues that come back), organization policy
(fix-by days, never-scan list), asset business context and import,
the ATT&CK mapping, lookalike domains, and account security
(two-factor sign-in, API keys, sign-in history).
"""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import SimpleTestCase, override_settings
from django.utils import timezone

from apps.api import totp
from apps.api.models import ApiKey, TwoFactorDevice
from apps.api.tests import JSON, OrgTestCase, make_finding
from apps.assets.models import Asset, Technology
from apps.audit_logs.models import ActivityEvent, AuthEvent
from apps.findings.models import Finding, FindingComment
from apps.findings.tasks import expire_risk_acceptances
from apps.notifications.models import NotificationRule
from apps.organizations.deletion import delete_organization
from apps.organizations.models import Membership, Organization
from apps.scanning.models import ScanJob
from apps.scanning.plugins.base import RawFinding
from apps.scanning.plugins.lookalike_domains import LookalikeDomainScanner, permutations, split_domain
from apps.scanning.tasks import fan_out_domain_scan, run_scan_job


def host(org, value, **extra):
    return Asset.objects.create(organization=org, value=value, asset_type=Asset.AssetType.SUBDOMAIN, **extra)


class FixPlanTests(OrgTestCase):
    def setUp(self):
        self.shop = host(self.org, "shop.acme.com")
        self.mail = host(self.org, "mail.acme.com", criticality=Asset.Criticality.CROWN_JEWEL)
        hsts = {"header": "Strict-Transport-Security"}
        make_finding(self.asset, "Missing HSTS", Finding.Severity.LOW,
                     finding_type=Finding.FindingType.MISSING_HEADER, raw_data=hsts)
        make_finding(self.shop, "Missing HSTS", Finding.Severity.LOW,
                     finding_type=Finding.FindingType.MISSING_HEADER, raw_data=hsts)
        make_finding(self.shop, "Open port 3389/tcp (ms-wbt-server)", Finding.Severity.HIGH,
                     raw_data={"port": 3389})
        make_finding(self.mail, "Open port 6379/tcp (redis)", Finding.Severity.HIGH, raw_data={"port": 6379})
        make_finding(self.mail, "Environment file exposed", Finding.Severity.CRITICAL,
                     finding_type=Finding.FindingType.EXPOSED_FILE, raw_data={"check": "env_file"})
        # Inventory, info and triaged findings are not work to do.
        make_finding(self.shop, "Open port 443/tcp (https)", Finding.Severity.INFO, raw_data={"port": 443})
        make_finding(self.shop, "shop.acme.com", Finding.Severity.INFO,
                     finding_type=Finding.FindingType.SUBDOMAIN_DISCOVERED)
        make_finding(self.shop, "Open port 22/tcp", Finding.Severity.MEDIUM,
                     raw_data={"port": 22}, status=Finding.Status.ACCEPTED)

    def plan(self):
        self.login("viewer")
        response = self.client.get(f"/api/organizations/{self.org.id}/fix-plan/")
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_groups_issues_by_the_action_that_fixes_them_worst_first(self):
        plan = self.plan()
        steps = plan["steps"]
        self.assertEqual(plan["open_issues"], 6)
        self.assertEqual([s["action"] for s in steps], [
            "Environment file exposed",
            # Two highs: the one on a crown jewel comes first.
            "Open port 6379/tcp (redis)",
            "Open port 3389/tcp (ms-wbt-server)",
            "Missing HSTS",
        ])
        hsts = steps[-1]
        self.assertEqual((hsts["issues"], hsts["hosts"]), (2, 2))
        self.assertEqual(steps[0]["crown_jewels"], 1)
        self.assertIn("Strict-Transport-Security", hsts["remediation"])
        self.assertEqual({i["asset_value"] for i in hsts["items"]}, {"acme.com", "shop.acme.com"})

    def test_projected_grade_only_improves_and_ends_clean(self):
        plan = self.plan()
        # The critical caps today's grade at C.
        self.assertEqual(plan["current_grade"], "C")
        scores = [plan["current_score"]] + [s["score_after"] for s in plan["steps"]]
        self.assertEqual(scores, sorted(scores))
        # Only the info finding is left: 99, an A+.
        self.assertEqual(plan["steps"][-1]["grade_after"], "A+")
        # Fixing the critical alone lifts the cap to B.
        self.assertEqual(plan["steps"][0]["grade_after"], "B")

    def test_empty_when_nothing_is_open(self):
        Finding.objects.all().delete()
        plan = self.plan()
        self.assertEqual(plan["steps"], [])
        self.assertIsNone(plan["current_grade"])


class InventoryTests(OrgTestCase):
    def setUp(self):
        self.shop = host(self.org, "shop.acme.com")
        Technology.objects.create(asset=self.asset, name="nginx", version="1.18.0", category="web-server")
        Technology.objects.create(asset=self.shop, name="nginx", version="1.18.0", category="web-server")
        Technology.objects.create(asset=self.shop, name="WordPress", version="6.4")
        make_finding(self.shop, "Open port 3389/tcp", raw_data={"port": 3389, "protocol": "tcp",
                                                               "service": "ms-wbt-server", "product": "RDP"})
        make_finding(self.asset, "Open port 443/tcp", Finding.Severity.INFO,
                     raw_data={"port": 443, "protocol": "tcp", "service": "https"})
        soon = (timezone.now() + timedelta(days=10)).isoformat()
        later = (timezone.now() + timedelta(days=200)).isoformat()
        make_finding(self.asset, "TLS certificate expires in 200 days", Finding.Severity.INFO,
                     finding_type=Finding.FindingType.EXPIRED_SSL, raw_data={"not_after": later})
        make_finding(self.shop, "TLS certificate expires in 10 days", Finding.Severity.MEDIUM,
                     finding_type=Finding.FindingType.EXPIRED_SSL, raw_data={"not_after": soon})
        self.login("viewer")

    def get(self, what):
        response = self.client.get(f"/api/organizations/{self.org.id}/{what}/")
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_technologies_group_hosts_by_software_and_version(self):
        rows = self.get("technologies")
        self.assertEqual(rows[0]["name"], "nginx")
        self.assertEqual(rows[0]["host_count"], 2)
        self.assertEqual(rows[1]["name"], "WordPress")

    def test_services_list_riskiest_ports_first(self):
        rows = self.get("services")
        self.assertEqual([r["port"] for r in rows], [3389, 443])
        self.assertEqual(rows[0]["hosts"][0]["product"], "RDP")

    def test_certificates_soonest_to_expire_first(self):
        rows = self.get("certificates")
        self.assertEqual([r["asset_value"] for r in rows], ["shop.acme.com", "acme.com"])
        self.assertIn(rows[0]["days_remaining"], (9, 10))

    def test_an_expired_certificate_counts_whole_days_ago(self):
        expired = (timezone.now() - timedelta(days=12, hours=3)).isoformat()
        make_finding(host(self.org, "legacy.acme.com"), "TLS certificate expired 12 days ago", Finding.Severity.CRITICAL,
                     finding_type=Finding.FindingType.EXPIRED_SSL, raw_data={"not_after": expired})
        self.assertEqual(self.get("certificates")[0]["days_remaining"], -12)

    def test_outsiders_see_nothing(self):
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(f"/api/organizations/{self.org.id}/services/").status_code, 404)


class CommentsAndTimelineTests(OrgTestCase):
    def setUp(self):
        self.finding = make_finding(self.asset, "Open port 3389/tcp")

    def comment(self, body):
        return self.client.post(f"/api/findings/{self.finding.id}/comments/", data={"body": body}, content_type=JSON)

    def test_any_member_can_discuss_a_finding(self):
        self.login("viewer")
        response = self.comment("  Fixed in tonight's deploy  ")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["body"], "Fixed in tonight's deploy")
        self.assertEqual(response.json()["author_name"], "viewer")
        self.assertEqual(self.comment("   ").status_code, 400)
        listed = self.client.get(f"/api/findings/{self.finding.id}/comments/").json()
        self.assertEqual([c["body"] for c in listed], ["Fixed in tonight's deploy"])

    def test_outsiders_cannot_read_or_write(self):
        self.client.force_login(self.outsider)
        self.assertEqual(self.comment("hi").status_code, 404)
        self.assertEqual(self.client.get(f"/api/findings/{self.finding.id}/timeline/").status_code, 404)

    def test_timeline_tells_the_story_in_order(self):
        self.login("analyst")
        self.client.post(f"/api/findings/{self.finding.id}/assign/",
                         data={"assignee": self.users["analyst"].id}, content_type=JSON)
        self.comment("Looking at it")
        self.client.post(f"/api/findings/{self.finding.id}/triage/",
                         data={"status": "accepted", "note": "Jump host"}, content_type=JSON)
        timeline = self.client.get(f"/api/findings/{self.finding.id}/timeline/").json()
        kinds = [entry["kind"] for entry in timeline]
        self.assertEqual(kinds, ["detected", "finding_assigned", "comment", "finding_triaged"])
        self.assertEqual(timeline[2]["text"], "Looking at it")

        # A later scan confirming it adds a line, in time order.
        Finding.objects.filter(id=self.finding.id).update(
            first_seen=timezone.now() - timedelta(days=3), last_seen=timezone.now() + timedelta(seconds=1)
        )
        timeline = self.client.get(f"/api/findings/{self.finding.id}/timeline/").json()
        self.assertEqual(timeline[-1]["kind"], "seen")


class BulkActionTests(OrgTestCase):
    def setUp(self):
        self.findings = [make_finding(self.asset, f"Issue {i}") for i in range(3)]
        self.ids = [str(f.id) for f in self.findings]

    def bulk(self, **body):
        return self.client.post("/api/findings/bulk/", data=body, content_type=JSON)

    def test_analyst_triages_many_at_once(self):
        self.login("analyst")
        until = (timezone.localdate() + timedelta(days=30)).isoformat()
        response = self.bulk(ids=self.ids, action="triage", status="accepted", note="Q4 project", accepted_until=until)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["updated"], 3)
        self.assertEqual(
            set(Finding.objects.values_list("status", "accepted_until")),
            {(Finding.Status.ACCEPTED, timezone.localdate() + timedelta(days=30))},
        )
        self.assertEqual(ActivityEvent.objects.filter(verb=ActivityEvent.Verb.FINDING_TRIAGED).count(), 3)

    def test_assigns_many_at_once(self):
        self.login("analyst")
        response = self.bulk(ids=self.ids, action="assign", assignee=self.users["viewer"].id)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(Finding.objects.values_list("assignee", flat=True)), {self.users["viewer"].id})
        self.assertEqual(self.bulk(ids=self.ids, action="assign", assignee=self.outsider.id).status_code, 400)

    def test_viewers_cannot_and_other_organizations_findings_are_refused(self):
        self.login("viewer")
        self.assertEqual(self.bulk(ids=self.ids, action="triage", status="accepted").status_code, 403)
        other = Organization.objects.create(name="Other", root_domain="other.com")
        stranger = make_finding(host(other, "x.other.com"), "Not yours")
        self.login("analyst")
        response = self.bulk(ids=self.ids + [str(stranger.id)], action="triage", status="accepted")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Finding.objects.filter(status=Finding.Status.ACCEPTED).exists())


class RiskAcceptanceExpiryTests(OrgTestCase):
    def setUp(self):
        self.finding = make_finding(self.asset, "Open port 3389/tcp")

    def triage(self, **body):
        return self.client.post(f"/api/findings/{self.finding.id}/triage/", data=body, content_type=JSON)

    def test_end_date_must_be_in_the_future_and_only_for_accepted(self):
        self.login("analyst")
        today = timezone.localdate()
        self.assertEqual(self.triage(status="accepted", accepted_until=today.isoformat()).status_code, 400)
        self.assertEqual(
            self.triage(status="false_positive", accepted_until=(today + timedelta(days=5)).isoformat()).status_code,
            400,
        )
        response = self.triage(status="accepted", accepted_until=(today + timedelta(days=5)).isoformat())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["accepted_until"], (today + timedelta(days=5)).isoformat())
        # Reopening clears the end date.
        self.assertIsNone(self.triage(status="open").json()["accepted_until"])

    def test_expired_acceptances_reopen(self):
        self.finding.status = Finding.Status.ACCEPTED
        self.finding.accepted_until = timezone.localdate() - timedelta(days=1)
        self.finding.save()
        still_valid = make_finding(self.asset, "Other", status=Finding.Status.ACCEPTED,
                                   accepted_until=timezone.localdate() + timedelta(days=3))
        expire_risk_acceptances()
        self.finding.refresh_from_db()
        still_valid.refresh_from_db()
        self.assertEqual(self.finding.status, Finding.Status.OPEN)
        self.assertIsNone(self.finding.accepted_until)
        self.assertEqual(still_valid.status, Finding.Status.ACCEPTED)
        event = ActivityEvent.objects.get(verb=ActivityEvent.Verb.ACCEPTANCE_EXPIRED)
        self.assertEqual((event.finding, event.actor_name), (self.finding, "System"))


@patch("apps.scanning.tasks.assert_public_target")
@patch("apps.scanning.tasks.notify_new_findings.delay")
class ComeBackTests(OrgTestCase):
    def run_scanner(self, findings):
        class Fake:
            applies_to = "asset"
            owned_finding_types = [Finding.FindingType.OPEN_PORT]
            name = "fake"

            def run(self, target):
                return findings

            def extract_technologies(self, target):
                return []

        job = ScanJob.objects.create(organization=self.org, asset=self.asset, scanner_name="nmap",
                                     idempotency_key=f"k{ScanJob.objects.count()}")
        with patch("apps.scanning.tasks.get_scanner", return_value=Fake):
            run_scan_job.run(str(job.id))

    def test_a_fixed_issue_that_reappears_is_flagged(self, *_):
        port = RawFinding(finding_type=Finding.FindingType.OPEN_PORT, identifier="3389/tcp",
                          severity=Finding.Severity.HIGH, title="Open port 3389/tcp")
        self.run_scanner([port])
        self.run_scanner([])  # fixed
        finding = Finding.objects.get()
        self.assertFalse(finding.is_active)
        self.assertEqual(finding.reopened_count, 0)
        self.run_scanner([port])  # back again
        finding.refresh_from_db()
        self.assertTrue(finding.is_active)
        self.assertEqual(finding.reopened_count, 1)
        self.assertIsNotNone(finding.reopened_at)
        self.assertTrue(ActivityEvent.objects.filter(verb=ActivityEvent.Verb.FINDING_REOPENED, finding=finding).exists())

        self.login("viewer")
        listed = self.client.get(f"/api/findings/?organization={self.org.id}&regressed=true").json()
        self.assertEqual(listed["count"], 1)

    def test_seen_again_while_still_open_is_not_a_regression(self, *_):
        port = RawFinding(finding_type=Finding.FindingType.OPEN_PORT, identifier="22/tcp",
                          severity=Finding.Severity.MEDIUM, title="Open port 22/tcp")
        self.run_scanner([port])
        self.run_scanner([port])
        self.assertEqual(Finding.objects.get().reopened_count, 0)


class SlaPolicyTests(OrgTestCase):
    def patch_org(self, role, **body):
        self.login(role)
        return self.client.patch(f"/api/organizations/{self.org.id}/", data=body, content_type=JSON)

    def test_admin_sets_days_to_fix_and_deadlines_follow(self):
        finding = make_finding(self.asset, "Open port 3389/tcp", Finding.Severity.HIGH)
        Finding.objects.filter(id=finding.id).update(first_seen=timezone.now() - timedelta(days=20))
        self.login("viewer")
        overdue = f"/api/findings/?organization={self.org.id}&overdue=true"
        self.assertEqual(self.client.get(overdue).json()["count"], 0)  # default: 30 days for high

        response = self.patch_org("admin", sla_days={"critical": 3, "high": 14})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["sla_days"], {"critical": 3, "high": 14, "medium": 90, "low": 180})
        self.login("viewer")
        self.assertEqual(self.client.get(overdue).json()["count"], 1)
        self.assertTrue(self.client.get(f"/api/findings/{finding.id}/").json()["overdue"])
        summary = self.client.get(f"/api/organizations/{self.org.id}/risk-summary/").json()
        self.assertEqual(summary["remediation"]["overdue"], 1)
        self.assertEqual(summary["remediation"]["sla_days"]["high"], 14)

    def test_more_serious_issues_cannot_get_longer(self):
        self.assertEqual(self.patch_org("admin", sla_days={"critical": 60}).status_code, 400)
        self.assertEqual(self.patch_org("admin", sla_days={"urgent": 1}).status_code, 400)
        self.assertEqual(self.patch_org("analyst", sla_days={"critical": 3}).status_code, 403)


@override_settings(REQUIRE_DOMAIN_VERIFICATION=False)
class ScopeExclusionTests(OrgTestCase):
    def setUp(self):
        self.shop = host(self.org, "shop.acme.com")
        self.agency = host(self.org, "www.agency.acme.com")
        self.api = host(self.org, "api.acme.com")

    def exclude(self, patterns, role="admin"):
        self.login(role)
        return self.client.patch(f"/api/organizations/{self.org.id}/", data={"scope_exclusions": patterns},
                                 content_type=JSON)

    def test_patterns_are_validated_and_cleaned(self):
        for bad in [["evil.com"], ["acme.com"], ["not a host"]]:
            with self.subTest(bad=bad):
                self.assertEqual(self.exclude(bad).status_code, 400)
        response = self.exclude([" Shop.acme.com. ", "*.agency.acme.com", "shop.acme.com"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scope_exclusions"], ["shop.acme.com", "*.agency.acme.com"])
        self.assertTrue(ActivityEvent.objects.filter(verb=ActivityEvent.Verb.SCOPE_CHANGED).exists())
        self.assertEqual(self.exclude(["shop.acme.com"], role="analyst").status_code, 403)

    def test_excluded_hosts_are_flagged_and_never_scanned(self):
        self.exclude(["shop.acme.com", "*.agency.acme.com"])
        assets = {a["value"]: a["out_of_scope"] for a in self.client.get("/api/assets/").json()["results"]}
        self.assertEqual(assets, {"acme.com": False, "api.acme.com": False,
                                  "shop.acme.com": True, "www.agency.acme.com": True})

        self.login("analyst")
        with patch("apps.api.views.run_scan_job.delay") as queued:
            response = self.client.post("/api/scan-jobs/trigger/",
                                        data={"scanner_name": "nmap", "asset_id": str(self.shop.id)},
                                        content_type=JSON)
        self.assertEqual(response.status_code, 400)
        queued.assert_not_called()

        with patch("apps.scanning.tasks.run_scan_job.delay"):
            fan_out_domain_scan(str(self.org.id), "nmap", "11111111-1111-1111-1111-111111111111")
        self.assertEqual(
            set(ScanJob.objects.values_list("asset__value", flat=True)), {"acme.com", "api.acme.com"}
        )

    def test_a_job_queued_before_the_exclusion_is_refused_when_it_runs(self):
        job = ScanJob.objects.create(organization=self.org, asset=self.shop, scanner_name="ssl_expiry")
        self.org.scope_exclusions = ["shop.acme.com"]
        self.org.save()
        run_scan_job.run(str(job.id))
        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.FAILED)
        self.assertIn("out of scope", job.error_message)


class AssetContextTests(OrgTestCase):
    def setUp(self):
        self.shop = host(self.org, "shop.acme.com")

    def patch_asset(self, body, role="analyst"):
        self.login(role)
        return self.client.patch(f"/api/assets/{self.shop.id}/", data=body, content_type=JSON)

    def test_analyst_sets_importance_and_labels(self):
        response = self.patch_asset({"criticality": "crown_jewel", "tags": ["Payments", "production ", "payments"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["criticality"], "crown_jewel")
        self.assertEqual(response.json()["tags"], ["payments", "production"])
        self.assertTrue(ActivityEvent.objects.filter(verb=ActivityEvent.Verb.ASSET_UPDATED).exists())

        self.assertEqual([a["value"] for a in self.client.get("/api/assets/?tag=payments").json()["results"]],
                         ["shop.acme.com"])
        self.assertEqual(self.client.get("/api/assets/?criticality=crown_jewel").json()["count"], 1)
        make_finding(self.shop, "Open port 3389/tcp")
        make_finding(self.asset, "Open port 22/tcp")
        crown = self.client.get(f"/api/findings/?organization={self.org.id}&asset_criticality=crown_jewel").json()
        self.assertEqual([f["asset_value"] for f in crown["results"]], ["shop.acme.com"])
        self.assertEqual(crown["results"][0]["asset_criticality"], "crown_jewel")

    def test_viewers_cannot_and_bad_values_are_refused(self):
        self.assertEqual(self.patch_asset({"criticality": "crown_jewel"}, role="viewer").status_code, 403)
        self.assertEqual(self.patch_asset({"criticality": "extreme"}).status_code, 400)
        self.assertEqual(self.patch_asset({"tags": ["x" * 31]}).status_code, 400)
        self.assertEqual(self.patch_asset({"tags": [f"t{i}" for i in range(11)]}).status_code, 400)
        # The value itself can't be edited this way.
        self.patch_asset({"value": "evil.com"})
        self.shop.refresh_from_db()
        self.assertEqual(self.shop.value, "shop.acme.com")

    def test_assets_cannot_be_deleted_or_replaced(self):
        self.login("owner")
        self.assertEqual(self.client.delete(f"/api/assets/{self.shop.id}/").status_code, 405)
        self.assertEqual(self.client.put(f"/api/assets/{self.shop.id}/", data={}, content_type=JSON).status_code, 405)


class BulkImportTests(OrgTestCase):
    def test_adds_what_it_can_and_explains_the_rest(self):
        self.login("analyst")
        response = self.client.post("/api/assets/bulk/", data={
            "organization": str(self.org.id),
            "values": ["vpn.acme.com", "VPN.acme.com", "", "evil.com", "acme.com", "mail.acme.com"],
        }, content_type=JSON)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["added"], ["vpn.acme.com", "mail.acme.com"])
        self.assertEqual([s["value"] for s in body["skipped"]], ["VPN.acme.com", "evil.com", "acme.com"])
        self.assertIn("already being monitored", body["skipped"][0]["reason"])
        self.assertEqual(Asset.objects.filter(source=Asset.Source.MANUAL).count(), 2)

    def test_viewers_cannot_import(self):
        self.login("viewer")
        response = self.client.post("/api/assets/bulk/", data={"organization": str(self.org.id),
                                                               "values": ["vpn.acme.com"]}, content_type=JSON)
        self.assertEqual(response.status_code, 403)


class AttackMappingTests(OrgTestCase):
    def test_issues_name_the_attacker_technique(self):
        finding = make_finding(self.asset, "Open port 3389/tcp")
        # A web server on 443 is a record, not a problem: it doesn't count against a control.
        make_finding(self.asset, "Open port 443/tcp", Finding.Severity.INFO)
        self.login("viewer")
        controls = {c["id"] for c in self.client.get(f"/api/findings/{finding.id}/").json()["controls"]}
        self.assertIn("attack:T1133", controls)
        frameworks = self.client.get(f"/api/organizations/{self.org.id}/compliance/").json()["frameworks"]
        attack = next(f for f in frameworks if f["id"] == "attack")
        self.assertEqual(attack["name"], "MITRE ATT&CK (Enterprise)")
        remote = next(c for c in attack["controls"] if c["id"] == "attack:T1133")
        self.assertEqual(remote["open_issues"], 1)


class LookalikeDomainTests(SimpleTestCase):
    def test_splits_registrable_names(self):
        self.assertEqual(split_domain("acme-retail.com"), ("acme-retail", "com"))
        self.assertEqual(split_domain("shop.acme.co.uk"), ("acme", "co.uk"))

    def test_generates_the_usual_lookalikes(self):
        variants = permutations("acme-retail.com")
        for expected, technique in [
            ("acmeretail.com", "hyphen removed"),
            ("acme-retai1.com", "look-alike character"),
            ("acme-retial.com", "swapped letters"),
            ("acme-retail.net", "different ending"),
            ("acme-retail-login.com", "added word"),
            ("acme-rretail.com", "doubled letter"),
        ]:
            with self.subTest(expected=expected):
                self.assertEqual(variants.get(expected), technique)
        self.assertNotIn("acme-retail.com", variants)
        self.assertTrue(all(not d.startswith("-") and "--" not in d for d in variants))

    def test_reports_registered_lookalikes_and_ignores_wildcard_endings(self):
        def records(_, name, record_type):
            if name.endswith(".xyz"):  # answers for anything
                return ["198.51.100.9"] if record_type == "A" else []
            if name == "acmeretail.com":
                return ["mx.acmeretail.com"] if record_type == "MX" else ["203.0.113.5"]
            if name == "acme-retail.net":
                return ["203.0.113.7"] if record_type == "A" else []
            return []

        org = Organization(name="Acme", root_domain="acme-retail.com")
        with patch.object(LookalikeDomainScanner, "_records", records):
            findings = LookalikeDomainScanner().run(org)
        found = {f.identifier: f for f in findings}
        self.assertEqual(set(found), {"acmeretail.com", "acme-retail.net"})
        self.assertEqual(found["acmeretail.com"].severity, Finding.Severity.MEDIUM)
        self.assertEqual(found["acmeretail.com"].raw_data["check"], "lookalike_mail")
        self.assertEqual(found["acme-retail.net"].severity, Finding.Severity.LOW)
        self.assertTrue(all(f.asset_value == "acme-retail.com" for f in findings))


class TwoFactorTests(OrgTestCase):
    def login_request(self, **extra):
        return self.client.post("/api/auth/login/", data={"username": "viewer", "password": "pass12345!", **extra},
                                content_type=JSON)

    def code(self, secret, offset=0):
        return totp.code_at(secret, totp.current_step() + offset)

    # The clock is pinned: a 30-second step must not roll over mid-test.
    @patch("apps.api.totp.time.time", return_value=1_800_000_015.0)
    @patch("apps.api.auth_views.ScopedRateThrottle.allow_request", return_value=True)
    def test_turning_on_two_factor_and_signing_in_with_it(self, *_):
        self.login("viewer")
        setup = self.client.post("/api/auth/2fa/setup/").json()
        self.assertTrue(setup["qr_svg"].startswith("<svg"))
        self.assertIn("otpauth://totp/", setup["otpauth_uri"])
        secret = setup["secret"]

        # Not on until a code is confirmed: password alone still works.
        self.assertEqual(self.login_request().status_code, 200)
        self.assertEqual(self.client.post("/api/auth/2fa/confirm/", data={"code": "000000"},
                                          content_type=JSON).status_code, 400)
        self.login("viewer")
        confirmed = self.client.post("/api/auth/2fa/confirm/", data={"code": self.code(secret, -1)}, content_type=JSON)
        self.assertEqual(confirmed.status_code, 200)
        self.assertTrue(self.client.get("/api/auth/2fa/").json()["enabled"])

        asked = self.login_request()
        self.assertEqual(asked.status_code, 400)
        self.assertTrue(asked.json()["otp_required"])
        self.assertNotIn("access", asked.json())
        self.assertEqual(self.login_request(otp="123456").status_code, 400)
        good = self.login_request(otp=self.code(secret))
        self.assertEqual(good.status_code, 200)
        self.assertIn("access", good.json())
        # The same code can't be used twice.
        self.assertEqual(self.login_request(otp=self.code(secret)).status_code, 400)
        self.assertTrue(AuthEvent.objects.filter(event_type=AuthEvent.EventType.TWO_FACTOR_ENABLED).exists())

    def test_wrong_password_never_reveals_two_factor(self):
        TwoFactorDevice.objects.create(user=self.users["viewer"], secret=totp.new_secret(), confirmed_at=timezone.now())
        response = self.client.post("/api/auth/login/", data={"username": "viewer", "password": "wrong"},
                                    content_type=JSON)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("otp_required", response.json())

    def test_turning_it_off_needs_the_password(self):
        TwoFactorDevice.objects.create(user=self.users["viewer"], secret=totp.new_secret(), confirmed_at=timezone.now())
        self.login("viewer")
        self.assertEqual(self.client.post("/api/auth/2fa/disable/", data={"password": "nope"},
                                          content_type=JSON).status_code, 400)
        self.assertEqual(self.client.post("/api/auth/2fa/setup/").status_code, 400)  # already on
        response = self.client.post("/api/auth/2fa/disable/", data={"password": "pass12345!"}, content_type=JSON)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(TwoFactorDevice.objects.exists())


class TotpTests(SimpleTestCase):
    # RFC 6238 appendix B, SHA-1, last six digits.
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    def test_matches_the_rfc_test_vectors(self):
        self.assertEqual(totp.code_at(self.SECRET, 59 // 30), "287082")
        self.assertEqual(totp.code_at(self.SECRET, 1111111109 // 30), "081804")
        self.assertEqual(totp.code_at(self.SECRET, 2000000000 // 30), "279037")

    def test_accepts_one_step_of_clock_drift_only(self):
        now = 1111111109
        self.assertIsNotNone(totp.matching_step(self.SECRET, "081804", now=now + 30))
        self.assertIsNone(totp.matching_step(self.SECRET, "081804", now=now + 90))
        self.assertIsNone(totp.matching_step(self.SECRET, "abc", now=now))


class ApiKeyTests(OrgTestCase):
    def test_keys_are_shown_once_and_only_read(self):
        self.login("analyst")
        created = self.client.post("/api/auth/api-keys/", data={"name": "SIEM"}, content_type=JSON)
        self.assertEqual(created.status_code, 201)
        key = created.json()["key"]
        self.assertTrue(key.startswith("sasm_"))
        listed = self.client.get("/api/auth/api-keys/").json()
        self.assertEqual([k["name"] for k in listed], ["SIEM"])
        self.assertNotIn("key", listed[0])
        self.assertFalse(ApiKey.objects.filter(key_hash=key).exists())  # only the hash is stored
        self.client.logout()

        headers = {"HTTP_AUTHORIZATION": f"Api-Key {key}"}
        response = self.client.get(f"/api/findings/?organization={self.org.id}", **headers)
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(ApiKey.objects.get().last_used_at)
        # Same tenant rules as the person: nothing from other organizations.
        other = Organization.objects.create(name="Other", root_domain="other.com")
        self.assertEqual(self.client.get(f"/api/organizations/{other.id}/", **headers).status_code, 404)
        # Read-only.
        with patch("apps.api.views.run_scan_job.delay") as queued:
            response = self.client.post("/api/scan-jobs/trigger/", data={"scanner_name": "nmap",
                                        "asset_id": str(self.asset.id)}, content_type=JSON, **headers)
        self.assertEqual(response.status_code, 403)
        queued.assert_not_called()

        self.login("analyst")
        self.assertEqual(self.client.delete(f"/api/auth/api-keys/{ApiKey.objects.get().id}/").status_code, 204)
        self.client.logout()
        self.assertEqual(self.client.get("/api/assets/", **headers).status_code, 401)

    def test_people_only_see_and_revoke_their_own_keys(self):
        api_key, _ = ApiKey.issue(self.users["admin"], "Admin's key")
        self.login("analyst")
        self.assertEqual(self.client.get("/api/auth/api-keys/").json(), [])
        self.assertEqual(self.client.delete(f"/api/auth/api-keys/{api_key.id}/").status_code, 404)


class SignInHistoryTests(OrgTestCase):
    def test_shows_your_own_sign_ins_and_attempts_on_your_name(self):
        AuthEvent.objects.create(event_type=AuthEvent.EventType.LOGIN_SUCCESS, user=self.users["viewer"],
                                 attempted_username="viewer", ip_address="203.0.113.1")
        AuthEvent.objects.create(event_type=AuthEvent.EventType.LOGIN_FAILED, attempted_username="viewer")
        AuthEvent.objects.create(event_type=AuthEvent.EventType.LOGIN_SUCCESS, user=self.users["admin"],
                                 attempted_username="admin")
        self.login("viewer")
        events = self.client.get("/api/auth/sign-ins/").json()
        self.assertEqual(sorted(e["event_type"] for e in events), ["login_failed", "login_success"])
        self.assertEqual(next(e for e in events if e["event_type"] == "login_success")["ip_address"], "203.0.113.1")


class DeletionWithNewDataTests(OrgTestCase):
    def test_organization_with_comments_and_history_deletes_cleanly(self):
        finding = make_finding(self.asset, "Open port 3389/tcp")
        FindingComment.objects.create(finding=finding, author=self.users["owner"], author_name="owner", body="hi")
        ActivityEvent.objects.create(organization=self.org, finding=finding, actor_name="owner",
                                     verb=ActivityEvent.Verb.FINDING_COMMENTED, summary="x")
        removed = delete_organization(self.org)
        self.assertEqual((removed["comments"], removed["findings"]), (1, 1))
        self.assertFalse(Organization.objects.filter(id=self.org.id).exists())
        self.assertFalse(Membership.objects.filter(organization_id=self.org.id).exists())
        self.assertTrue(User.objects.filter(username="owner").exists())


class HeatmapTests(OrgTestCase):
    def test_counts_open_issues_by_kind_and_severity_heaviest_first(self):
        make_finding(self.asset, "rdp", Finding.Severity.HIGH)
        make_finding(self.asset, "ssh", Finding.Severity.LOW)
        make_finding(self.asset, "web", Finding.Severity.INFO)  # not an issue
        make_finding(self.asset, "accepted", Finding.Severity.CRITICAL, status=Finding.Status.ACCEPTED)
        make_finding(self.asset, ".env", Finding.Severity.CRITICAL, finding_type=Finding.FindingType.EXPOSED_FILE)
        self.login("viewer")
        body = self.client.get(f"/api/organizations/{self.org.id}/heatmap/").json()
        self.assertEqual(body["severities"], ["critical", "high", "medium", "low"])
        self.assertEqual([r["finding_type"] for r in body["rows"]], ["exposed_file", "open_port"])
        self.assertEqual(body["rows"][1]["counts"], {"critical": 0, "high": 1, "medium": 0, "low": 1})
        self.assertEqual(body["rows"][1]["total"], 2)


class AlertSetupTests(OrgTestCase):
    def test_test_alert_by_email_arrives_and_says_what_it_is(self):
        from django.core import mail

        rule = NotificationRule.objects.create(organization=self.org, recipient_email="sec@acme.com",
                                               min_severity=Finding.Severity.HIGH)
        self.login("admin")
        response = self.client.post(f"/api/notification-rules/{rule.id}/test/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["delivered"])
        self.assertEqual(mail.outbox[0].to, ["sec@acme.com"])
        self.assertIn("critical and high issues", mail.outbox[0].body)
        self.login("analyst")
        self.assertEqual(self.client.post(f"/api/notification-rules/{rule.id}/test/").status_code, 403)

    def test_test_alert_to_a_dead_webhook_explains_what_to_check(self):
        rule = NotificationRule.objects.create(
            organization=self.org, channel=NotificationRule.Channel.WEBHOOK,
            webhook_url="https://hooks.example.com/x", min_severity=Finding.Severity.HIGH,
        )
        self.login("admin")
        with patch("apps.notifications.tasks._post_text", return_value=False):
            body = self.client.post(f"/api/notification-rules/{rule.id}/test/").json()
        self.assertFalse(body["delivered"])
        self.assertIn("incoming-webhook", body["detail"])

    def test_alert_volume_counts_new_issues_of_the_last_30_days(self):
        make_finding(self.asset, "new rdp", Finding.Severity.HIGH)
        make_finding(self.asset, "new subdomain", Finding.Severity.INFO,
                     finding_type=Finding.FindingType.SUBDOMAIN_DISCOVERED)
        old = make_finding(self.asset, "old", Finding.Severity.CRITICAL)
        Finding.objects.filter(id=old.id).update(first_seen=timezone.now() - timedelta(days=45))
        self.login("viewer")
        body = self.client.get(f"/api/organizations/{self.org.id}/alert-volume/").json()
        self.assertEqual(body["new_issues"], {"info": 0, "low": 0, "medium": 0, "high": 1, "critical": 0})

    def test_alert_email_reads_plainly(self):
        from django.core import mail
        from apps.notifications.tasks import notify_new_findings

        NotificationRule.objects.create(organization=self.org, recipient_email="sec@acme.com",
                                        min_severity=Finding.Severity.HIGH)
        finding = make_finding(self.asset, "Database dump is publicly downloadable", Finding.Severity.CRITICAL)
        notify_new_findings.run("ignored", [str(finding.id)])
        self.assertEqual(mail.outbox[0].subject, "Densight: 1 new security issue on Acme")
        self.assertIn("What to do next", mail.outbox[0].body)
        self.assertIn("critical and high issues", mail.outbox[0].body)


class WebhookSecrecyTests(OrgTestCase):
    def test_only_admins_see_the_whole_webhook_link(self):
        NotificationRule.objects.create(
            organization=self.org, channel=NotificationRule.Channel.WEBHOOK,
            webhook_url="https://hooks.slack.com/services/T0/B0/secret", min_severity=Finding.Severity.HIGH,
        )
        for role, expected in [("viewer", "https://hooks.slack.com/…"), ("analyst", "https://hooks.slack.com/…"),
                               ("admin", "https://hooks.slack.com/services/T0/B0/secret")]:
            with self.subTest(role=role):
                self.login(role)
                rules = self.client.get(f"/api/notification-rules/?organization={self.org.id}").json()["results"]
                self.assertEqual(rules[0]["webhook_url"], expected)
