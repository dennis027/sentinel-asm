"""
Secrets in JavaScript, public cloud storage and domain registration.
Parsers and decisions are tested without the network.
"""

from datetime import datetime, timezone as dt_timezone
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.assets.models import Asset
from apps.findings.models import Finding
from apps.organizations.models import Organization
from apps.scanning.plugins.cloud_storage import CloudStorageScanner, candidate_names, listing
from apps.scanning.plugins.domain_expiry import parse, server_for
from apps.scanning.plugins.http_util import Page
from apps.scanning.plugins.js_secrets import JsSecretsScanner, find_secrets, mask, script_urls

STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc9xA"
GITHUB = "ghp_" + "A" * 4 + "b1C2d3E4f5G6h7I8j9K0l1M2n3O4p5Q6r7S8"


class JsSecretsTests(SimpleTestCase):
    def test_finds_server_side_keys_and_ignores_public_ones_and_placeholders(self):
        code = (f'const stripe = "{STRIPE}"; const pk = "pk_live_51Habc123def456ghi789jkl";'
                f' fetch("/x", {{headers: {{t: "{GITHUB}"}}}}); const demo = "AKIAIOSFODNN7EXAMPLE";'
                ' const maps = "REMOVED_SAMPLE_KEY";')
        found = {kind.kind: value for kind, value in find_secrets(code)}
        self.assertEqual(set(found), {"stripe_secret", "github_token", "google_api_key"})
        self.assertEqual(mask(STRIPE), "sk_liv…c9xA")

    def test_only_scripts_from_the_site_or_the_organizations_domain(self):
        html = ('<script src="/static/app.js"></script><script src="https://cdn.acme.com/v.js"></script>'
                '<script src="https://cdn.jsdelivr.net/npm/x.js"></script><script>var k="x";</script>'
                '<script src="//evil.com/a.js"></script>')
        urls, inline = script_urls("https://www.acme.com/", html, "www.acme.com", "acme.com")
        self.assertEqual(urls, ["https://www.acme.com/static/app.js", "https://cdn.acme.com/v.js"])
        self.assertEqual(inline, ['var k="x";'])

    def test_run_reports_each_secret_once_with_the_file_and_never_the_full_value(self):
        org = Organization(name="Acme", root_domain="acme.com")
        asset = Asset(value="www.acme.com", organization=org)

        def fake_fetch(host, path="/", **kwargs):
            if path == "/":
                return Page(200, {}, '<script src="/app.js"></script><script src="/vendor.js"></script>',
                            "https://www.acme.com/")
            return Page(200, {}, f'var s="{STRIPE}";', f"https://{host}{path}")

        with patch("apps.scanning.plugins.js_secrets.fetch", side_effect=fake_fetch):
            findings = JsSecretsScanner().run(asset)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding.severity, finding.title), ("critical", "Stripe secret key in public JavaScript (app.js)"))
        self.assertNotIn(STRIPE, finding.description + str(finding.raw_data))
        self.assertEqual(finding.raw_data["masked"], "sk_liv…c9xA")


class CloudStorageTests(SimpleTestCase):
    def test_candidate_names(self):
        names = candidate_names("acme-retail.example", "Acme Retail")
        self.assertEqual(names[:3], ["acme-retail", "acme-retail-backup", "acme-retail-backups"])
        self.assertIn("acmeretail-assets", names)
        self.assertTrue(all(3 <= len(n) <= 63 and n == n.lower() for n in names))
        self.assertEqual(len(names), len(set(names)))

    def test_listing(self):
        body = ('<?xml version="1.0"?><ListBucketResult><Name>acme-backups</Name><Contents><Key>db/2026-10-01.sql.gz'
                '</Key></Contents><Contents><Key>users.csv</Key></Contents></ListBucketResult>')
        self.assertEqual(listing(body), (True, ["db/2026-10-01.sql.gz", "users.csv"]))
        self.assertEqual(listing("<Error><Code>AccessDenied</Code></Error>"), (False, []))

    def test_run_reports_only_listable_buckets_and_follows_region_redirects(self):
        def fake_fetch(host, path, **kwargs):
            if host == "acme-backups.s3.amazonaws.com":
                return Page(301, {"Location": ""}, "<Error><Endpoint>acme-backups.s3.eu-west-1.amazonaws.com"
                                                   "</Endpoint></Error>", "")
            if host == "acme-backups.s3.eu-west-1.amazonaws.com":
                return Page(200, {}, "<ListBucketResult><Key>backup.sql</Key></ListBucketResult>", "")
            if host == "storage.googleapis.com" and path.startswith("/acme-static?"):
                return Page(200, {}, "<ListBucketResult></ListBucketResult>", "")
            if host == "acme.s3.amazonaws.com":
                return Page(403, {}, "<Error><Code>AccessDenied</Code></Error>", "")
            return Page(404, {}, "<Error><Code>NoSuchBucket</Code></Error>", "")

        with patch("apps.scanning.plugins.cloud_storage.fetch", side_effect=fake_fetch):
            findings = CloudStorageScanner().run(Organization(name="Acme", root_domain="acme.com"))
        got = {f.identifier: f.severity for f in findings}
        self.assertEqual(got, {"s3:acme-backups": "high", "gcs:acme-static": "medium"})
        backups = next(f for f in findings if f.identifier == "s3:acme-backups")
        self.assertIn("backup.sql", backups.description)
        self.assertEqual(backups.raw_data["url"], "https://acme-backups.s3.eu-west-1.amazonaws.com/")

    def test_no_network_is_an_error_not_a_clean_result(self):
        with patch("apps.scanning.plugins.cloud_storage.fetch", side_effect=RuntimeError("offline")):
            with self.assertRaises(RuntimeError):
                CloudStorageScanner().run(Organization(name="Acme", root_domain="acme.com"))


BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                          [["co.uk", "uk"], ["https://rdap.nominet.uk/uk"]]]}


def rdap(expires, status=("client transfer prohibited",)):
    return {"events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
                       {"eventAction": "expiration", "eventDate": expires}],
            "status": list(status),
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                           ["fn", {}, "text", "Example Registrar"]]]}]}


class DomainExpiryTests(SimpleTestCase):
    now = datetime(2026, 10, 17, tzinfo=dt_timezone.utc)

    def test_server_for(self):
        self.assertEqual(server_for("acme.com", BOOTSTRAP), "https://rdap.verisign.com/com/v1/")
        self.assertEqual(server_for("shop.acme.co.uk", BOOTSTRAP), "https://rdap.nominet.uk/uk/")
        self.assertIsNone(server_for("acme.ke", BOOTSTRAP))

    def test_expiry_thresholds_and_transfer_lock(self):
        def findings(expires, **kw):
            return {f.identifier: f.severity for f in parse("acme.com", rdap(expires, **kw), self.now)}

        self.assertEqual(findings("2027-06-01T00:00:00Z"), {})
        self.assertEqual(findings("2026-11-20T00:00:00Z"), {"expiry": "medium"})
        self.assertEqual(findings("2026-11-01T00:00:00Z"), {"expiry": "high"})
        self.assertEqual(findings("2026-10-20T00:00:00Z"), {"expiry": "critical"})
        expired = parse("acme.com", rdap("2026-10-10T00:00:00Z"), self.now)[0]
        self.assertEqual(expired.title, "acme.com expired 7 day(s) ago")
        self.assertIn("Example Registrar", expired.description)
        self.assertEqual(findings("2027-06-01T00:00:00Z", status=["active"]), {"transfer_lock": "low"})

    def test_finding_types_are_registered_with_guidance(self):
        from apps.findings.guidance import CHECK_GUIDANCE

        for check in ("exposed_secret", "public_bucket", "domain_expiring", "transfer_lock_off"):
            self.assertIn(check, CHECK_GUIDANCE)
        self.assertEqual(Finding.FindingType.PUBLIC_BUCKET, "public_bucket")
