"""
The attack surface features: the check before a scan (and skipping
hosts that no longer exist), what scans learn about each host (web
response, hosting), host owners, policies, the asset search language,
saved views, the change feed, emerging threats and getting started.
"""

import socket
import uuid
from datetime import date, timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.assets.hosting import detect_provider
from apps.assets.models import Asset, Technology
from apps.audit_logs.models import ActivityEvent
from apps.findings import policies
from apps.findings.emerging import matches
from apps.findings.models import Finding, KnownExploitedVulnerability
from apps.organizations.models import Membership, Organization, SavedView
from apps.scanning.models import ScanJob
from apps.scanning.plugins.base import RawFinding
from apps.scanning.plugins.httpx_scanner import page_title
from apps.scanning.tasks import WORKER_STATUS_KEY, run_scan_job

User = get_user_model()


def port_finding(asset, port, active=True):
    return Finding.objects.create(
        asset=asset, finding_type=Finding.FindingType.OPEN_PORT, severity=Finding.Severity.MEDIUM,
        title=f"Open port {port}/tcp", dedupe_key=Finding.build_dedupe_key("open_port", f"{port}/tcp"),
        raw_data={"port": str(port), "protocol": "tcp", "service": "ms-wbt-server"}, is_active=active,
        resolved_at=None if active else timezone.now(),
    )


class Fixture(TestCase):
    def setUp(self):
        cache.clear()
        self.org = Organization.objects.create(name="Acme", root_domain="acme.com")
        self.other_org = Organization.objects.create(name="Other", root_domain="other.com")
        self.users = {}
        for role in ("owner", "admin", "analyst", "viewer"):
            user = User.objects.create_user(role, email=f"{role}@acme.com", password="x-Password-42")
            Membership.objects.create(user=user, organization=self.org, role=role)
            self.users[role] = user
        self.outsider = User.objects.create_user("outsider", password="x-Password-42")
        Membership.objects.create(user=self.outsider, organization=self.other_org, role="owner")
        self.shop = Asset.objects.create(organization=self.org, value="shop.acme.com", asset_type="subdomain")
        self.dev = Asset.objects.create(organization=self.org, value="dev.acme.com", asset_type="subdomain")

    def as_user(self, role):
        self.client.force_login(self.users[role] if role in self.users else self.outsider)

    def get(self, url, role="viewer"):
        self.as_user(role)
        return self.client.get(url)

    def send(self, method, url, body=None, role="admin"):
        self.as_user(role)
        return getattr(self.client, method)(url, body or {}, content_type="application/json")


def fake_scanner(findings=(), facts=None, needs_address=True, applies_to="asset"):
    class Fake:
        name = "fake"
        owned_finding_types = [Finding.FindingType.OPEN_PORT]

        def run(self, target):
            return list(findings)

        def extract_technologies(self, target):
            return []

        def extract_asset_facts(self, target):
            return facts or {}

    Fake.needs_address = needs_address
    Fake.applies_to = applies_to
    return Fake


def run_job(asset, scanner):
    job = ScanJob.objects.create(organization=asset.organization, asset=asset, scanner_name="nmap",
                                 idempotency_key=f"k-{ScanJob.objects.count()}")
    with patch("apps.scanning.tasks.get_scanner", return_value=scanner), \
            patch("apps.scanning.tasks.notify_new_findings.delay"):
        run_scan_job.run(str(job.id))
    job.refresh_from_db()
    return job


class SkipUnreachableTests(Fixture):
    def no_such_name(self, *args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    def test_a_host_that_no_longer_exists_is_skipped_not_failed(self):
        with patch("apps.scanning.targets.socket.getaddrinfo", side_effect=self.no_such_name):
            job = run_job(self.shop, fake_scanner())
        self.assertEqual(job.status, ScanJob.Status.SKIPPED)
        self.assertIn("doesn't resolve", job.error_message)

    def test_dns_only_scanners_still_run_on_a_missing_name(self):
        with patch("apps.scanning.targets.socket.getaddrinfo", side_effect=self.no_such_name):
            job = run_job(self.shop, fake_scanner(needs_address=False))
        self.assertEqual(job.status, ScanJob.Status.SUCCESS)

    def test_a_resolver_that_does_not_answer_is_not_treated_as_missing(self):
        def no_answer(*args, **kwargs):
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure")

        with patch("apps.scanning.targets.socket.getaddrinfo", side_effect=no_answer):
            job = run_job(self.shop, fake_scanner())
        self.assertEqual(job.status, ScanJob.Status.SUCCESS)

    def test_reasons_group_a_runs_failures_by_cause(self):
        run_id = uuid.uuid4()
        for asset in (self.shop, self.dev):
            ScanJob.objects.create(
                organization=self.org, asset=asset, scanner_name="httpx", idempotency_key=asset.value, run_id=run_id,
                status=ScanJob.Status.SKIPPED,
                error_message=f"{asset.value} doesn't resolve in DNS, so there was nothing to connect to.",
            )
        response = self.get(f"/api/scan-jobs/reasons/?organization={self.org.id}&run_id={run_id}")
        self.assertEqual(response.status_code, 200)
        [group] = response.json()
        self.assertEqual((group["count"], group["status"]), (2, "skipped"))
        self.assertEqual(group["reason"], "the host doesn't resolve in DNS, so there was nothing to connect to.")
        self.assertEqual(sorted(group["hosts"]), ["dev.acme.com", "shop.acme.com"])


@patch("apps.scanning.tasks.assert_public_target")
class HostFactsTests(Fixture):
    def test_web_and_hosting_facts_are_stored_and_the_provider_worked_out(self, _guard):
        run_job(self.shop, fake_scanner(facts={"hosting": {"ips": ["104.16.1.1"], "cnames": [], "checked_at": "x"}}))
        run_job(self.shop, fake_scanner(facts={"web": {"status": 200, "title": "Acme shop", "server": "nginx"}}))
        self.shop.refresh_from_db()
        self.assertEqual(self.shop.web["title"], "Acme shop")
        self.assertEqual(self.shop.hosting["provider"], "Cloudflare")

    def test_new_issues_on_an_owned_host_go_to_its_owner(self, _guard):
        self.shop.owner = self.users["analyst"]
        self.shop.save()
        finding = RawFinding(finding_type="open_port", identifier="22/tcp", severity="high", title="Open port 22")
        run_job(self.shop, fake_scanner(findings=[finding]))
        self.assertEqual(Finding.objects.get(asset=self.shop).assignee, self.users["analyst"])


class HostingDetectionTests(SimpleTestCase):
    def test_providers_from_names_addresses_and_headers(self):
        self.assertEqual(detect_provider(cnames=["d111.cloudfront.net"]), "AWS")
        self.assertEqual(detect_provider(cnames=["shops.myshopify.com"]), "Shopify")
        self.assertEqual(detect_provider(addresses=["2606:4700::6810:1"]), "Cloudflare")
        self.assertEqual(detect_provider(reverse_names=["ec2-1-2-3-4.compute-1.amazonaws.com"]), "AWS")
        self.assertEqual(detect_provider(server="Vercel"), "Vercel")
        self.assertEqual(detect_provider(addresses=["203.0.113.9"], server="nginx"), "")

    def test_page_title(self):
        self.assertEqual(page_title(b"<html><head><TITLE>\n Acme &amp; Co </title>"), "Acme & Co")
        self.assertEqual(page_title(b"<html>no title</html>"), "")


class OwnerTests(Fixture):
    def test_an_analyst_can_set_an_owner_who_is_a_member(self):
        response = self.send("patch", f"/api/assets/{self.shop.id}/", {"owner": self.users["viewer"].id}, role="analyst")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["owner_name"], "viewer")
        self.assertTrue(ActivityEvent.objects.filter(summary__contains="owner viewer").exists())

    def test_the_owner_must_be_in_the_organization(self):
        response = self.send("patch", f"/api/assets/{self.shop.id}/", {"owner": self.outsider.id}, role="analyst")
        self.assertEqual(response.status_code, 400)

    def test_removing_a_member_clears_what_they_owned(self):
        self.shop.owner = self.users["viewer"]
        self.shop.save()
        membership = Membership.objects.get(user=self.users["viewer"])
        response = self.send("delete", f"/api/organizations/{self.org.id}/members/{membership.id}/")
        self.assertEqual(response.status_code, 204)
        self.shop.refresh_from_db()
        self.assertIsNone(self.shop.owner)


class PolicyTests(Fixture):
    def create(self, role="admin", **body):
        body = {"organization": str(self.org.id), "name": "No RDP", "kind": "port", "value": "3389",
                "severity": "high", **body}
        return self.send("post", "/api/surface-policies/", body, role=role)

    def test_a_port_policy_flags_hosts_and_resolves_when_the_port_closes(self):
        rdp = port_finding(self.shop, 3389)
        response = self.create(guidance="Put RDP behind the VPN.")
        self.assertEqual(response.status_code, 201, response.content)
        breach = Finding.objects.get(finding_type=Finding.FindingType.POLICY_VIOLATION)
        self.assertEqual((breach.asset, breach.severity, breach.is_active), (self.shop, "high", True))
        self.assertIn("Put RDP behind the VPN.", self.get(f"/api/findings/{breach.id}/").json()["remediation"])
        self.assertEqual(self.get(f"/api/surface-policies/?organization={self.org.id}").json()[0]["breaking"], 1)

        rdp.is_active = False
        rdp.save()
        policies.evaluate(self.org, [self.shop.id])
        breach.refresh_from_db()
        self.assertFalse(breach.is_active)

    def test_hostname_software_and_hosting_policies(self):
        Technology.objects.create(asset=self.shop, name="WordPress", version="6.1")
        self.shop.hosting = {"provider": "Heroku"}
        self.shop.save()
        self.create(name="No dev", kind="hostname", value="dev.*")
        self.create(name="No WordPress", kind="technology", value="wordpress")
        self.create(name="Off Heroku", kind="provider", value="heroku")
        broken = set(Finding.objects.filter(is_active=True).values_list("asset__value", "title"))
        self.assertEqual(broken, {
            ("dev.acme.com", "Breaks policy: No dev"),
            ("shop.acme.com", "Breaks policy: No WordPress"),
            ("shop.acme.com", "Breaks policy: Off Heroku"),
        })

    def test_turning_a_policy_off_or_deleting_it_resolves_its_findings(self):
        port_finding(self.shop, 3389)
        policy_id = self.create().json()["id"]
        self.send("patch", f"/api/surface-policies/{policy_id}/", {"enabled": False})
        self.assertFalse(Finding.objects.filter(finding_type="policy_violation", is_active=True).exists())
        self.send("patch", f"/api/surface-policies/{policy_id}/", {"enabled": True})
        self.send("delete", f"/api/surface-policies/{policy_id}/")
        self.assertFalse(Finding.objects.filter(finding_type="policy_violation", is_active=True).exists())

    def test_only_admins_change_policies_and_values_are_checked(self):
        self.assertEqual(self.create(role="analyst").status_code, 403)
        self.assertEqual(self.create(value="99999").status_code, 400)
        self.assertEqual(self.create(role="outsider").status_code, 403)
        self.assertEqual(self.get(f"/api/surface-policies/?organization={self.org.id}", role="outsider").json(), [])


class AssetQueryTests(Fixture):
    def search(self, q, role="analyst"):
        response = self.get(f"/api/assets/?organization={self.org.id}&q={q}", role=role)
        self.assertEqual(response.status_code, 200, response.content)
        return sorted(row["value"] for row in response.json()["results"])

    def test_each_kind_of_term(self):
        api = Asset.objects.create(organization=self.org, value="api.acme.com", asset_type="subdomain",
                                   tags=["payments"], owner=self.users["analyst"],
                                   hosting={"provider": "AWS"}, web={"status": 302})
        Technology.objects.create(asset=self.shop, name="nginx", version="1.24")
        port_finding(self.dev, 22)
        Finding.objects.create(asset=api, finding_type="weak_tls", severity="critical", title="TLS 1.0",
                               dedupe_key="tls")
        self.assertEqual(self.search("tech:nginx"), ["shop.acme.com"])
        self.assertEqual(self.search("tag:payments"), ["api.acme.com"])
        self.assertEqual(self.search("owner:me"), ["api.acme.com"])
        self.assertEqual(self.search("owner:none"), ["dev.acme.com", "shop.acme.com"])
        self.assertEqual(self.search("provider:aws"), ["api.acme.com"])
        self.assertEqual(self.search("status:3xx"), ["api.acme.com"])
        self.assertEqual(self.search("port:22"), ["dev.acme.com"])
        self.assertEqual(self.search("severity:high%2B"), ["api.acme.com"])
        self.assertEqual(self.search("-tag:payments shop"), ["shop.acme.com"])
        self.assertEqual(self.search("nonsense:thing"), [])


class SavedViewTests(Fixture):
    def save_view(self, role, **body):
        body = {"organization": str(self.org.id), "page": "findings", "name": "Criticals",
                "filters": {"severity": "critical"}, **body}
        return self.send("post", "/api/saved-views/", body, role=role)

    def test_views_are_private_unless_shared_and_only_their_author_edits_them(self):
        mine = self.save_view("viewer").json()
        shared = self.save_view("analyst", name="Team", shared=True).json()
        self.assertEqual(mine["filters"], {"severity": "critical"})
        names = [v["name"] for v in self.get(f"/api/saved-views/?organization={self.org.id}&page=findings", "analyst").json()]
        self.assertEqual(names, ["Team"])
        self.assertEqual(self.send("patch", f"/api/saved-views/{shared['id']}/", {"name": "Mine"}, role="viewer").status_code, 403)
        self.assertEqual(self.send("delete", f"/api/saved-views/{shared['id']}/", role="viewer").status_code, 403)
        self.assertEqual(self.send("delete", f"/api/saved-views/{shared['id']}/", role="admin").status_code, 204)
        self.assertEqual(self.get(f"/api/saved-views/?organization={self.org.id}", "outsider").json(), [])

    def test_filters_must_be_simple_values(self):
        self.assertEqual(self.save_view("viewer", filters={"a": {"b": 1}}).status_code, 400)
        self.assertEqual(SavedView.objects.count(), 0)


class SurfaceChangeTests(Fixture):
    def test_the_feed_lists_hosts_ports_and_software(self):
        Technology.objects.create(asset=self.shop, name="nginx", version="1.24")
        port_finding(self.shop, 3389)
        port_finding(self.dev, 23, active=False)
        body = self.get(f"/api/organizations/{self.org.id}/surface-changes/?days=30").json()
        self.assertEqual(body["counts"]["host_added"], 2)
        self.assertEqual(body["counts"]["port_opened"], 2)
        self.assertEqual(body["counts"]["port_closed"], 1)
        self.assertEqual(body["counts"]["software_seen"], 1)
        only_ports = self.get(f"/api/organizations/{self.org.id}/surface-changes/?kind=port_closed").json()
        self.assertEqual([e["detail"] for e in only_ports["events"]], ["23/tcp (ms-wbt-server)"])

    def test_other_organizations_cannot_see_it(self):
        self.assertEqual(self.get(f"/api/organizations/{self.org.id}/surface-changes/", "outsider").status_code, 404)


class EmergingThreatTests(Fixture):
    def test_name_matching(self):
        self.assertTrue(matches("Microsoft-IIS", "Microsoft", "Internet Information Services (IIS)"))
        self.assertTrue(matches("Confluence", "Atlassian", "Confluence Server and Data Center"))
        self.assertTrue(matches("GitLab", "GitLab", "GitLab CE/EE"))
        self.assertTrue(matches("Grafana", "Grafana Labs", "Grafana"))
        self.assertFalse(matches("nginx", "F5", "BIG-IP"))

    def test_recent_exploited_vulnerabilities_in_software_we_run(self):
        Technology.objects.create(asset=self.shop, name="Grafana", version="9.1.0")
        KnownExploitedVulnerability.objects.create(
            cve_id="CVE-2026-0001", vendor="Grafana Labs", product="Grafana", name="Grafana path traversal",
            date_added=date.today() - timedelta(days=3), ransomware=True,
        )
        KnownExploitedVulnerability.objects.create(
            cve_id="CVE-2020-0001", vendor="Grafana Labs", product="Grafana", name="old",
            date_added=date.today() - timedelta(days=400),
        )
        body = self.get(f"/api/organizations/{self.org.id}/emerging-threats/").json()
        [item] = body["items"]
        self.assertEqual((item["cve"], item["software"], item["confirmed"]), ("CVE-2026-0001", "Grafana", False))
        self.assertEqual(item["hosts"][0]["value"], "shop.acme.com")


@patch("apps.scanning.preflight.classify_host", side_effect=lambda host: "missing" if host.startswith("dev") else "ok")
class PreflightTests(Fixture):
    def test_it_reports_hosts_tools_and_worker(self, _classify):
        self.org.scope_exclusions = ["shop.acme.com"]
        self.org.save()
        Asset.objects.create(organization=self.org, value="www.acme.com", asset_type="subdomain")
        cache.set(WORKER_STATUS_KEY, {"seen_at": "now", "missing_tools": {"nmap": ["nmap"]}})
        body = self.get(f"/api/organizations/{self.org.id}/preflight/?scanners=nmap,httpx,subfinder").json()
        self.assertEqual((body["hosts"]["active"], body["hosts"]["in_scope"], body["hosts"]["excluded"]), (3, 2, 1))
        self.assertEqual((body["hosts"]["checked"], body["hosts"]["missing"]), (2, 1))
        self.assertEqual(body["hosts"]["missing_hosts"], ["dev.acme.com"])
        scanners = {s["name"]: s for s in body["scanners"]}
        self.assertEqual(scanners["nmap"]["missing_tools"], ["nmap"])
        self.assertEqual(scanners["httpx"]["likely_skipped"], 1)
        self.assertEqual(scanners["subfinder"]["targets"], 1)
        self.assertEqual(body["jobs"], 3)
        self.assertTrue(any("nmap isn't installed" in w for w in body["warnings"]))

    def test_no_worker_and_unknown_scanners(self, _classify):
        body = self.get(f"/api/organizations/{self.org.id}/preflight/").json()
        self.assertTrue(any("No scan worker" in w for w in body["warnings"]))
        self.assertEqual(self.get(f"/api/organizations/{self.org.id}/preflight/?scanners=nope").status_code, 400)


class GettingStartedTests(Fixture):
    def test_steps_follow_what_has_been_done(self):
        steps = {s["key"]: s["done"] for s in self.get(f"/api/organizations/{self.org.id}/getting-started/").json()["steps"]}
        self.assertTrue(steps["team"])
        self.assertFalse(steps["owners"])
        self.shop.owner = self.users["viewer"]
        self.shop.criticality = "crown_jewel"
        self.shop.save()
        body = self.get(f"/api/organizations/{self.org.id}/getting-started/").json()
        steps = {s["key"]: s["done"] for s in body["steps"]}
        self.assertTrue(steps["owners"] and steps["importance"])
        self.assertEqual(body["total"], 8)


class HostingTests(Fixture):
    def test_hosts_grouped_by_provider(self):
        self.shop.hosting = {"provider": "AWS", "ips": ["3.3.3.3"], "checked_at": "x"}
        self.dev.hosting = {"ips": ["3.3.3.3"], "checked_at": "x"}
        self.shop.save()
        self.dev.save()
        body = self.get(f"/api/organizations/{self.org.id}/hosting/").json()
        self.assertEqual(body["providers"], [{"provider": "AWS", "count": 1, "hosts": ["shop.acme.com"]}])
        self.assertEqual(body["unknown"]["count"], 1)
        self.assertEqual(body["shared_addresses"][0]["count"], 2)
