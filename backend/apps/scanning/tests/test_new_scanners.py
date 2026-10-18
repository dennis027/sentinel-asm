"""
The scanners added from the research round (admin panels, API
exposure, DNS hygiene, certificate transparency) and CISA KEV matching.
Parsers and decisions are tested without the network.
"""

import json
from datetime import datetime, timezone as dt_timezone
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase

from apps.assets.models import Asset
from apps.findings import kev
from apps.findings.insights import build_fix_plan
from apps.findings.models import Finding
from apps.organizations.models import Membership, Organization
from apps.scanning.plugins.admin_panels import PANELS, assess
from apps.scanning.plugins.api_exposure import introspection_types, spec_endpoints
from apps.scanning.plugins.cert_transparency import analyse
from apps.scanning.plugins.dns_hygiene import DnsHygieneScanner
from apps.scanning.plugins.http_util import Page


def panel(check):
    return next(p for p in PANELS if p.check == check)


class AdminPanelTests(SimpleTestCase):
    def test_a_panel_needs_its_signature_and_a_live_answer(self):
        found = assess("db.acme.com", panel("phpmyadmin"), "/phpmyadmin/", 200,
                       "<title>phpMyAdmin</title> Welcome to phpMyAdmin")
        self.assertEqual((found.severity, found.identifier), ("high", "phpmyadmin"))
        self.assertIsNone(assess("db.acme.com", panel("phpmyadmin"), "/phpmyadmin/", 200, "<h1>Our shop</h1>"))
        self.assertIsNone(assess("db.acme.com", panel("phpmyadmin"), "/phpmyadmin/", 404, "phpMyAdmin"))
        blocked = assess("ci.acme.com", panel("jenkins"), "/", 403, "", {"X-Jenkins": "2.346"})
        self.assertEqual(blocked.severity, "low")


class ApiExposureTests(SimpleTestCase):
    def test_recognises_openapi_documents_and_introspection(self):
        self.assertEqual(spec_endpoints(json.dumps({"openapi": "3.0.0", "paths": {"/a": {}, "/b": {}}})), 2)
        self.assertIsNone(spec_endpoints("<html>docs</html>"))
        self.assertIsNone(spec_endpoints(json.dumps({"paths": {}})))
        self.assertEqual(introspection_types(json.dumps({"data": {"__schema": {"types": [{"name": "Query"}] * 3}}})), 3)
        self.assertIsNone(introspection_types(json.dumps({"errors": [{"message": "introspection disabled"}]})))

    def test_run_reports_spec_and_graphql(self):
        from apps.scanning.plugins.api_exposure import ApiExposureScanner

        def fake_fetch(host, path, **kwargs):
            if path == "/openapi.json":
                return Page(200, {}, json.dumps({"swagger": "2.0", "paths": {"/users": {}}}), path)
            if path == "/graphql" and kwargs.get("method") == "POST":
                return Page(200, {}, json.dumps({"data": {"__schema": {"types": [1, 2]}}}), path)
            return Page(404, {}, "", path)

        with patch("apps.scanning.plugins.api_exposure.fetch", side_effect=fake_fetch):
            findings = ApiExposureScanner().run(Asset(value="api.acme.com"))
        self.assertEqual(sorted(f.identifier for f in findings), ["graphql_introspection", "openapi_spec"])


class DnsHygieneTests(SimpleTestCase):
    def test_flags_missing_caa_dnssec_wildcards_and_one_nameserver(self):
        answers = {("acme.com", "NS"): ["ns1.host.com"], ("acme.com", "CAA"): [], ("acme.com", "DNSKEY"): []}

        def records(_, name, record_type):
            if record_type == "A":
                return ["203.0.113.1"]  # the random name resolves: wildcard
            return answers[(name, record_type)]

        with patch.object(DnsHygieneScanner, "_records", records):
            findings = DnsHygieneScanner().run(Organization(root_domain="acme.com"))
        self.assertEqual(sorted(f.identifier for f in findings),
                         ["caa_missing", "dnssec_missing", "single_nameserver", "wildcard_dns"])

    def test_a_well_run_domain_is_clean(self):
        def records(_, name, record_type):
            return {"NS": ["ns1", "ns2"], "CAA": ['0 issue "letsencrypt.org"'], "DNSKEY": ["257 3 13 x"]}.get(record_type, [])

        with patch.object(DnsHygieneScanner, "_records", records):
            self.assertEqual(DnsHygieneScanner().run(Organization(root_domain="acme.com")), [])


class CertTransparencyTests(SimpleTestCase):
    def test_hostnames_recent_certificates_and_unusual_issuers(self):
        now = datetime(2026, 10, 17, tzinfo=dt_timezone.utc)
        le = "C=US, O=Let's Encrypt, CN=R11"
        entries = [
            {"id": i, "issuer_name": le, "name_value": "shop.acme.com\nwww.acme.com", "not_before": f"2026-10-0{i + 1}T00:00:00"}
            for i in range(3)
        ] + [
            {"id": 9, "issuer_name": "C=XX, O=Cheap Certs Ltd, CN=CA", "name_value": "login.acme.com",
             "not_before": "2026-10-10T00:00:00"},
            {"id": 10, "issuer_name": le, "name_value": "old.acme.com\n*.acme.com\nevil.com",
             "not_before": "2024-01-01T00:00:00"},
        ]
        findings = analyse("acme.com", entries, now)
        hosts = sorted(f.asset_value for f in findings if f.identifier.startswith("host:"))
        self.assertEqual(hosts, ["login.acme.com", "old.acme.com", "shop.acme.com", "www.acme.com"])
        certs = [f for f in findings if f.identifier.startswith("crt:")]
        self.assertEqual(len(certs), 4)  # the 2024 one is too old
        unusual = [f for f in findings if f.finding_type == Finding.FindingType.UNUSUAL_CERT]
        self.assertEqual([f.raw_data["issuer"] for f in unusual], ["Cheap Certs Ltd"])
        self.assertEqual(unusual[0].severity, "medium")


CATALOGUE = {
    "catalogVersion": "2026.10.17", "dateReleased": "2026-10-17T00:00:00Z", "count": 1,
    "vulnerabilities": [{
        "cveID": "CVE-2023-4966", "vendorProject": "Citrix", "product": "NetScaler ADC and NetScaler Gateway",
        "vulnerabilityName": "Citrix NetScaler Session Token Leak", "dateAdded": "2023-10-18",
        "shortDescription": "Sensitive information disclosure.", "requiredAction": "Apply updates.",
        "dueDate": "2023-11-08", "knownRansomwareCampaignUse": "Known",
    }],
}


class KnownExploitedTests(TestCase):
    def setUp(self):
        cache.clear()
        self.org = Organization.objects.create(name="Acme", root_domain="acme.com")
        self.vpn = Asset.objects.create(organization=self.org, value="vpn.acme.com", asset_type=Asset.AssetType.SUBDOMAIN)
        self.user = User.objects.create_user("viewer", password="pass12345!")
        Membership.objects.create(user=self.user, organization=self.org, role="viewer")

    def finding(self, title, severity, **extra):
        return Finding.objects.create(asset=self.vpn, finding_type=Finding.FindingType.NUCLEI_MATCH, severity=severity,
                                      title=title, dedupe_key=Finding.build_dedupe_key("t", title), **extra)

    def test_known_exploited_findings_are_flagged_filtered_and_first_in_the_plan(self):
        self.assertEqual(kev.load(CATALOGUE), 1)
        exploited = self.finding("NetScaler session leak", "high", raw_data={"template_id": "CVE-2023-4966"})
        self.finding("Some other critical issue", "critical", raw_data={"template_id": "CVE-2021-0000"})
        self.assertEqual(exploited.cves, ["CVE-2023-4966"])

        self.client.force_login(self.user)
        body = self.client.get(f"/api/findings/{exploited.id}/").json()
        self.assertEqual(body["known_exploited"]["date_added"], "2023-10-18")
        self.assertTrue(body["known_exploited"]["ransomware"])
        listed = self.client.get(f"/api/findings/?organization={self.org.id}&known_exploited=true").json()
        self.assertEqual([f["title"] for f in listed["results"]], ["NetScaler session leak"])

        # A known-exploited high outranks a critical nobody is known to exploit.
        steps = build_fix_plan(self.org)["steps"]
        self.assertEqual(steps[0]["action"], "NetScaler session leak")
        self.assertEqual(steps[0]["known_exploited"], 1)

    def test_sync_survives_being_offline(self):
        from apps.findings.tasks import sync_known_exploited

        with patch("apps.findings.kev.urllib.request.urlopen", side_effect=OSError("no route")):
            self.assertIn("keeping the copy", sync_known_exploited())

    def test_scans_record_the_cves_they_find(self):
        from apps.scanning.models import ScanJob
        from apps.scanning.plugins.base import RawFinding
        from apps.scanning.tasks import run_scan_job

        class Fake:
            applies_to = "asset"
            owned_finding_types = []
            name = "fake"

            def run(self, target):
                return [RawFinding(finding_type="nuclei_match", identifier="x", severity="critical",
                                   title="Citrix Bleed", raw_data={"info": {"classification": {"cve-id": ["cve-2023-4966"]}}})]

            def extract_technologies(self, target):
                return []

        job = ScanJob.objects.create(organization=self.org, asset=self.vpn, scanner_name="nuclei")
        with patch("apps.scanning.tasks.get_scanner", return_value=Fake), \
                patch("apps.scanning.tasks.assert_public_target"), \
                patch("apps.scanning.tasks.notify_new_findings.delay"):
            run_scan_job.run(str(job.id))
        self.assertEqual(Finding.objects.get(title="Citrix Bleed").cves, ["CVE-2023-4966"])
