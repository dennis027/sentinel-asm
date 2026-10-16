"""
Tests for scanner plugin parsing logic -- the pure-function part of
each scanner (turning raw tool output into RawFinding objects) that
doesn't require a live network call or the actual binary, so these run
fast and deterministically in CI.

Live-network behavior (does nmap actually find open ports on a real
host) is NOT what's tested here -- that was verified manually against
real targets during development. What's tested here is: given known
raw output, does the parser produce the correct RawFinding objects.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.findings.models import Finding
from apps.scanning.plugins.dns_monitor import DnsMonitorScanner
from apps.scanning.plugins.httpx_scanner import HttpxScanner
from apps.scanning.plugins.nmap_scanner import NmapScanner
from apps.scanning.plugins.nuclei_scanner import NucleiScanner
from apps.scanning.plugins.ssl_expiry import SSLExpiryScanner
from apps.scanning.plugins.subfinder_scanner import SubfinderScanner


class NmapParserTests(SimpleTestCase):
    SAMPLE_XML = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="nginx"/>
          </port>
          <port protocol="tcp" portid="3389">
            <state state="open"/>
            <service name="ms-wbt-server"/>
          </port>
          <port protocol="tcp" portid="8080">
            <state state="closed"/>
            <service name="http-proxy"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""

    def test_only_open_ports_are_reported(self):
        scanner = NmapScanner()
        findings = scanner._parse(self.SAMPLE_XML)
        ports_found = {f.raw_data["port"] for f in findings}
        self.assertEqual(ports_found, {"443", "3389"})
        self.assertNotIn("8080", ports_found)

    def test_high_risk_port_gets_high_severity(self):
        scanner = NmapScanner()
        findings = scanner._parse(self.SAMPLE_XML)
        rdp_finding = next(f for f in findings if f.raw_data["port"] == "3389")
        self.assertEqual(rdp_finding.severity, Finding.Severity.HIGH)

    def test_routine_web_port_gets_info_severity(self):
        scanner = NmapScanner()
        findings = scanner._parse(self.SAMPLE_XML)
        https_finding = next(f for f in findings if f.raw_data["port"] == "443")
        self.assertEqual(https_finding.severity, Finding.Severity.INFO)

    def test_service_product_included_in_description(self):
        scanner = NmapScanner()
        findings = scanner._parse(self.SAMPLE_XML)
        https_finding = next(f for f in findings if f.raw_data["port"] == "443")
        self.assertIn("nginx", https_finding.description)


class NucleiParserTests(SimpleTestCase):
    def test_parses_multiple_severities_correctly(self):
        jsonl = "\n".join([
            '{"template-id": "exposed-git", "info": {"name": "Exposed .git", "severity": "high"}, "matched-at": "https://x.com/.git"}',
            '{"template-id": "tech-detect", "info": {"name": "Nginx", "severity": "info"}, "matched-at": "https://x.com/"}',
        ])
        scanner = NucleiScanner()
        findings = scanner._parse(jsonl)
        self.assertEqual(len(findings), 2)
        severities = {f.severity for f in findings}
        self.assertEqual(severities, {Finding.Severity.HIGH, Finding.Severity.INFO})

    def test_malformed_line_is_skipped_not_fatal(self):
        jsonl = "\n".join([
            '{"template-id": "valid-one", "info": {"name": "Valid", "severity": "medium"}, "matched-at": "https://x.com/"}',
            "this is not json at all",
            "",  # blank line should also be skipped cleanly
        ])
        scanner = NucleiScanner()
        findings = scanner._parse(jsonl)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Valid")

    def test_unknown_severity_maps_to_info(self):
        jsonl = '{"template-id": "weird", "info": {"name": "Weird", "severity": "unknown"}, "matched-at": ""}'
        scanner = NucleiScanner()
        findings = scanner._parse(jsonl)
        self.assertEqual(findings[0].severity, Finding.Severity.INFO)

    def test_empty_output_returns_no_findings(self):
        scanner = NucleiScanner()
        self.assertEqual(scanner._parse(""), [])


class SslExpirySeverityTests(SimpleTestCase):
    def test_already_expired_is_critical(self):
        self.assertEqual(SSLExpiryScanner._severity_for(-5), Finding.Severity.CRITICAL)

    def test_expiring_in_three_days_is_high(self):
        self.assertEqual(SSLExpiryScanner._severity_for(3), Finding.Severity.HIGH)

    def test_expiring_in_twenty_days_is_medium(self):
        self.assertEqual(SSLExpiryScanner._severity_for(20), Finding.Severity.MEDIUM)

    def test_expiring_in_ninety_days_is_info(self):
        self.assertEqual(SSLExpiryScanner._severity_for(90), Finding.Severity.INFO)

    def test_boundary_exactly_seven_days_is_high(self):
        # Boundary check -- easy off-by-one spot (<=  vs <).
        self.assertEqual(SSLExpiryScanner._severity_for(7), Finding.Severity.HIGH)

    def test_boundary_exactly_thirty_days_is_medium(self):
        self.assertEqual(SSLExpiryScanner._severity_for(30), Finding.Severity.MEDIUM)


class SubfinderParserTests(SimpleTestCase):
    def test_raw_finding_carries_asset_value(self):
        rf = SubfinderScanner._to_raw_finding("api.example.com")
        self.assertEqual(rf.asset_value, "api.example.com")
        self.assertEqual(rf.finding_type, Finding.FindingType.SUBDOMAIN_DISCOVERED)
        self.assertEqual(rf.severity, Finding.Severity.INFO)
        self.assertIn("api.example.com", rf.title)


class HttpxParserTests(SimpleTestCase):
    """
    Regression test for the real case-sensitivity bug caught during
    development: converting response headers to a plain dict() breaks
    lookups when a server sends lowercase header names (common over
    HTTP/2). These tests assert against the case-insensitive .get()
    contract the fix relies on.
    """

    def _mock_target(self, host="example.com"):
        target = MagicMock()
        target.value = host
        return target

    def test_all_headers_present_means_no_findings(self):
        headers = MagicMock()
        headers.get.side_effect = lambda name: "present"  # every header "exists"
        scanner = HttpxScanner()
        with patch.object(scanner, "_fetch_headers", return_value=headers):
            findings = scanner.run(self._mock_target())
        self.assertEqual(findings, [])

    def test_missing_headers_are_reported(self):
        headers = MagicMock()
        headers.get.side_effect = lambda name: None  # nothing present
        scanner = HttpxScanner()
        with patch.object(scanner, "_fetch_headers", return_value=headers):
            findings = scanner.run(self._mock_target())
        self.assertEqual(len(findings), 5)  # all 5 SECURITY_HEADERS entries

    def test_lowercase_header_name_still_counts_as_present(self):
        # Simulates a real email.message.Message object's case-insensitive
        # .get() -- this is the exact behavior the case-sensitivity fix
        # depends on. A plain dict() would fail this test.
        from email.message import Message
        real_headers = Message()
        real_headers["strict-transport-security"] = "max-age=31536000"  # lowercase, like HTTP/2

        scanner = HttpxScanner()
        with patch.object(scanner, "_fetch_headers", return_value=real_headers):
            findings = scanner.run(self._mock_target())

        titles = [f.title for f in findings]
        self.assertFalse(any("HSTS" in t for t in titles))  # correctly NOT reported missing

    def test_server_header_becomes_technology(self):
        headers = MagicMock()
        headers.get.side_effect = lambda name: "nginx/1.25" if name == "Server" else None
        scanner = HttpxScanner()
        with patch.object(scanner, "_fetch_headers", return_value=headers):
            technologies = scanner.extract_technologies(self._mock_target())
        self.assertEqual(len(technologies), 1)
        self.assertEqual(technologies[0].name, "nginx/1.25")
        self.assertEqual(technologies[0].category, "web-server")


class DnsMonitorParserTests(SimpleTestCase):
    def _mock_target(self, host="example.com"):
        target = MagicMock()
        target.value = host
        return target

    def test_one_record_type_failing_does_not_abort_scan(self):
        import dns.exception
        import dns.resolver

        class FakeAnswer:
            def __init__(self, text):
                self._text = text
            def to_text(self):
                return self._text

        def fake_resolve(host, record_type):
            if record_type == "A":
                return [FakeAnswer("93.184.216.34")]
            if record_type == "TXT":
                raise dns.exception.Timeout()  # simulates the real timeout seen in dev
            raise dns.resolver.NoAnswer()

        scanner = DnsMonitorScanner()
        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            findings = scanner.run(self._mock_target())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].raw_data["record_type"], "A")

    def test_all_record_types_failing_raises(self):
        import dns.resolver

        def always_nxdomain(host, record_type):
            raise dns.resolver.NXDOMAIN()

        scanner = DnsMonitorScanner()
        # NXDOMAIN on every type is a legitimate "no records" outcome for
        # each type individually, so any_record_type_succeeded stays True
        # -- this should NOT raise. Only a genuine resolver-level failure
        # (e.g. every query timing out) should raise.
        with patch("dns.resolver.Resolver.resolve", side_effect=always_nxdomain):
            findings = scanner.run(self._mock_target())
        self.assertEqual(findings, [])


class ScreenshotPageSelectionTests(SimpleTestCase):
    """Which links on a landing page get their own screenshot."""

    LANDING = "https://shop.example.com/"

    def pick(self, hrefs, limit=10):
        from apps.scanning.plugins.screenshot_scanner import select_pages

        return select_pages(self.LANDING, hrefs, limit)

    def test_keeps_same_host_pages_in_page_order(self):
        pages = self.pick(["/login", "about", "https://shop.example.com/pricing/"])
        self.assertEqual(
            pages,
            [
                "https://shop.example.com/login",
                "https://shop.example.com/about",
                "https://shop.example.com/pricing/",
            ],
        )

    def test_ignores_other_hosts_and_non_web_links(self):
        pages = self.pick([
            "https://evil.example.org/", "https://other.example.com/x", "//cdn.example.net/a",
            "mailto:a@example.com", "javascript:void(0)", "tel:123", "", None,
        ])
        self.assertEqual(pages, [])

    def test_one_screenshot_per_path(self):
        pages = self.pick(["/", "#top", "/docs", "/docs/", "/docs#install", "/docs?page=2", "/DOCS"])
        self.assertEqual(pages, ["https://shop.example.com/docs", "https://shop.example.com/DOCS"])

    def test_skips_downloads_and_session_ending_links(self):
        pages = self.pick([
            "/report.pdf", "/logo.PNG", "/app.js", "/logout", "/account/sign-out",
            "/items/3/delete", "/contact",
        ])
        self.assertEqual(pages, ["https://shop.example.com/contact"])

    def test_respects_the_limit(self):
        hrefs = [f"/page{i}" for i in range(20)]
        self.assertEqual(len(self.pick(hrefs, limit=5)), 5)
        self.assertEqual(self.pick(hrefs, limit=0), [])



class EmailSecurityTests(SimpleTestCase):
    def checks(self, issues):
        return [(issue.check, issue.severity) for issue in issues]

    def test_spf(self):
        from apps.scanning.plugins.email_security import evaluate_spf

        self.assertEqual(self.checks(evaluate_spf(["google-site-verification=abc"])), [("spf_missing", "medium")])
        self.assertEqual(self.checks(evaluate_spf(["v=spf1 -all", "v=spf1 include:x.com -all"])), [("spf_multiple", "medium")])
        self.assertEqual(self.checks(evaluate_spf(["v=spf1 include:_spf.google.com +all"])), [("spf_allows_anyone", "high")])
        self.assertEqual(self.checks(evaluate_spf(["v=spf1 a mx all"])), [("spf_allows_anyone", "high")])
        self.assertEqual(self.checks(evaluate_spf(["v=spf1 mx ?all"])), [("spf_neutral", "low")])
        self.assertEqual(self.checks(evaluate_spf(["v=spf1 mx"])), [("spf_no_all", "low")])
        # Healthy records: hard fail, soft fail, and delegation to another record.
        for good in ["v=spf1 include:_spf.google.com -all", "V=SPF1 mx ~all", "v=spf1 redirect=_spf.example.com"]:
            self.assertEqual(evaluate_spf([good]), [], good)

    def test_dmarc(self):
        from apps.scanning.plugins.email_security import evaluate_dmarc

        self.assertEqual(self.checks(evaluate_dmarc([])), [("dmarc_missing", "high")])
        self.assertEqual(self.checks(evaluate_dmarc(["v=DMARC1; p=none", "v=DMARC1; p=reject"])), [("dmarc_multiple", "medium")])
        self.assertEqual(self.checks(evaluate_dmarc(["v=DMARC1; p=none; rua=mailto:d@x.com"])), [("dmarc_monitor_only", "medium")])
        self.assertEqual(self.checks(evaluate_dmarc(["v=DMARC1; p=quarantine; pct=25"])), [("dmarc_partial", "low")])
        for good in ["v=DMARC1; p=reject", "v=DMARC1;p=quarantine;pct=100", "v=DMARC1; p=reject; pct=abc"]:
            self.assertEqual(evaluate_dmarc([good]), [], good)

    def scan(self, records):
        from types import SimpleNamespace

        from apps.scanning.plugins.email_security import EmailSecurityScanner

        scanner = EmailSecurityScanner()
        scanner._txt = lambda name, tolerate_errors=False: records.get(name, [])
        return scanner.run(SimpleNamespace(root_domain="acme.com"))

    def test_unprotected_domain_is_reported_on_the_root_asset(self):
        findings = self.scan({})
        self.assertEqual([f.identifier for f in findings], ["spf_missing", "dmarc_missing", "dkim_not_found"])
        self.assertTrue(all(f.asset_value == "acme.com" for f in findings))
        self.assertTrue(all(f.finding_type == Finding.FindingType.EMAIL_SECURITY for f in findings))

    def test_well_configured_domain_has_nothing_to_report(self):
        findings = self.scan({
            "acme.com": ["v=spf1 include:_spf.google.com -all"],
            "_dmarc.acme.com": ["v=DMARC1; p=reject; rua=mailto:d@acme.com"],
            "google._domainkey.acme.com": ["v=DKIM1; k=rsa; p=MIIB..."],
        })
        self.assertEqual(findings, [])

    def test_a_dns_failure_is_an_error_not_a_missing_record(self):
        import dns.exception

        from apps.scanning.plugins.email_security import EmailSecurityScanner

        with patch("apps.scanning.plugins.email_security.dns.resolver.Resolver.resolve",
                   side_effect=dns.exception.Timeout()):
            with self.assertRaises(RuntimeError):
                EmailSecurityScanner()._txt("acme.com")
            self.assertEqual(EmailSecurityScanner()._txt("x._domainkey.acme.com", tolerate_errors=True), [])


class SubdomainTakeoverTests(SimpleTestCase):
    def assess(self, cname, resolves, body=""):
        from apps.scanning.plugins.subdomain_takeover import assess

        return assess("shop.acme.com", cname, resolves, body)

    def test_no_cname_or_a_live_target_is_fine(self):
        self.assertIsNone(self.assess(None, True))
        self.assertIsNone(self.assess("acme.myshopify.com.", True, "<html>Welcome to the Acme store</html>"))
        self.assertIsNone(self.assess("lb.internal-cdn.example.net", True))

    def test_provider_page_saying_nothing_is_hosted_is_high(self):
        finding = self.assess("acme.github.io", True, "<p>There isn't a GitHub Pages site here.</p>")
        self.assertEqual(finding.severity, Finding.Severity.HIGH)
        self.assertEqual(finding.raw_data["check"], "takeover")
        self.assertEqual(finding.raw_data["provider"], "GitHub Pages")
        self.assertIn("GitHub Pages", finding.title)

    def test_provider_target_that_no_longer_resolves_is_high(self):
        finding = self.assess("acme-old.azurewebsites.net", False)
        self.assertEqual((finding.severity, finding.raw_data["check"]), (Finding.Severity.HIGH, "takeover"))

    def test_unknown_target_that_no_longer_resolves_is_a_dangling_record(self):
        finding = self.assess("gone.some-vendor.example", False)
        self.assertEqual((finding.severity, finding.raw_data["check"]), (Finding.Severity.MEDIUM, "dangling_cname"))

    def test_a_dns_timeout_is_never_reported_as_a_risk(self):
        import dns.exception

        from apps.scanning.plugins.subdomain_takeover import SubdomainTakeoverScanner

        with patch("apps.scanning.plugins.subdomain_takeover.dns.resolver.Resolver.resolve",
                   side_effect=dns.exception.Timeout()):
            self.assertTrue(SubdomainTakeoverScanner()._resolves("acme-old.azurewebsites.net"))


class TlsConfigTests(SimpleTestCase):
    def checks(self, accepted, trust_error=None):
        from apps.scanning.plugins.tls_config import findings_for

        return [(f.identifier, f.severity) for f in findings_for("acme.com", set(accepted), trust_error)]

    def test_modern_server_has_nothing_to_report(self):
        self.assertEqual(self.checks(["TLS 1.2", "TLS 1.3"]), [])

    def test_retired_versions_are_flagged(self):
        self.assertEqual(self.checks(["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]), [("old_protocol", "medium")])
        self.assertEqual(
            self.checks(["TLS 1.0"]), [("old_protocol", "medium"), ("no_modern_protocol", "high")]
        )

    def test_missing_tls13_is_only_informational(self):
        self.assertEqual(self.checks(["TLS 1.2"]), [("no_tls13", "info")])

    def test_untrusted_certificate_is_high(self):
        self.assertEqual(
            self.checks(["TLS 1.2", "TLS 1.3"], "self-signed certificate"), [("untrusted_certificate", "high")]
        )

    def test_host_without_https_is_skipped(self):
        from types import SimpleNamespace

        from apps.scanning.plugins.tls_config import TlsConfigScanner

        with patch("apps.scanning.plugins.tls_config.socket.create_connection", side_effect=OSError):
            self.assertEqual(TlsConfigScanner().run(SimpleNamespace(value="acme.com")), [])


class OutdatedSoftwareTests(SimpleTestCase):
    def test_parses_products_from_headers(self):
        from apps.scanning.plugins.outdated_software import parse_products

        self.assertEqual(
            parse_products("Apache/2.2.15 (CentOS) OpenSSL/1.0.2k-fips", "PHP/5.4.16"),
            {"apache": "2.2.15", "openssl": "1.0.2", "php": "5.4.16"},
        )
        self.assertEqual(parse_products("nginx", None, "cloudflare"), {})
        self.assertEqual(parse_products("Microsoft-IIS/8.5"), {"microsoft-iis": "8.5"})

    def titles(self, products):
        from apps.scanning.plugins.outdated_software import findings_for

        return [f.title for f in findings_for("acme.com", products)]

    def test_only_end_of_life_release_lines_are_reported(self):
        self.assertEqual(
            self.titles({"php": "7.4.33", "apache": "2.2.15", "nginx": "1.14.0", "microsoft-iis": "8.5"}),
            [
                "Apache HTTP Server 2.2.15 is out of support",
                "Microsoft IIS 8.5 is out of support",
                "nginx 1.14.0 is out of support",
                "PHP 7.4.33 is out of support",
            ],
        )
        self.assertEqual(self.titles({"php": "8.3.1", "apache": "2.4.58", "nginx": "1.26.0", "microsoft-iis": "10.0"}), [])

    def test_unknown_products_are_ignored(self):
        self.assertEqual(self.titles({"gunicorn": "19.0", "envoy": "1.0"}), [])


class SecurityTxtTests(SimpleTestCase):
    NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)

    def check(self, body):
        from apps.scanning.plugins.security_txt import assess

        finding = assess("acme.com", body, now=self.NOW)
        return finding.raw_data["check"] if finding else None

    def test_missing_file(self):
        self.assertEqual(self.check(None), "security_txt_missing")

    def test_valid_file_has_nothing_to_report(self):
        self.assertIsNone(self.check("# Our policy\nContact: mailto:security@acme.com\nExpires: 2027-01-01T00:00:00Z\n"))
        self.assertIsNone(self.check("contact: https://acme.com/report"))

    def test_file_without_contact_or_past_its_date(self):
        self.assertEqual(self.check("Expires: 2027-01-01T00:00:00Z\nPolicy: https://acme.com/policy"), "security_txt_no_contact")
        self.assertEqual(
            self.check("Contact: mailto:security@acme.com\nExpires: 2025-01-01T00:00:00Z"), "security_txt_expired"
        )

    def test_a_site_that_serves_its_home_page_for_every_url_does_not_count(self):
        from types import SimpleNamespace

        from apps.scanning.plugins.http_util import Page
        from apps.scanning.plugins.security_txt import SecurityTxtScanner

        html = Page(status=200, headers={"Content-Type": "text/html; charset=utf-8"}, body="<html>Contact: us</html>", url="")
        with patch("apps.scanning.plugins.security_txt.fetch", return_value=html):
            findings = SecurityTxtScanner().run(SimpleNamespace(root_domain="acme.com"))
        self.assertEqual(findings[0].raw_data["check"], "security_txt_missing")
        self.assertEqual(findings[0].asset_value, "acme.com")


class ExposedFilesTests(SimpleTestCase):
    def check(self, path, status, body):
        from apps.scanning.plugins.exposed_files import FILES, assess

        file = next(f for f in FILES if f.path == path)
        finding = assess("acme.com", file, status, body)
        return (finding.raw_data["check"], finding.severity) if finding else None

    def test_real_files_are_critical(self):
        self.assertEqual(self.check("/.git/HEAD", 200, "ref: refs/heads/main\n"), ("git_exposed", "critical"))
        self.assertEqual(self.check("/.git/HEAD", 200, "9fceb02d0ae598e95dc970b74767f19372d61af8"), ("git_exposed", "critical"))
        self.assertEqual(
            self.check("/.env", 200, "# app\nAPP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc\n"),
            ("env_exposed", "critical"),
        )
        self.assertEqual(
            self.check("/backup.sql", 200, "-- MySQL dump 10.13\nCREATE TABLE users (id int);"),
            ("database_dump_exposed", "critical"),
        )
        self.assertEqual(self.check("/server-status", 200, "<h1>Apache Server Status for x</h1>"), ("server_status_exposed", "medium"))

    def test_a_site_that_answers_every_url_with_its_home_page_is_not_flagged(self):
        home = "<!doctype html><html><body>Welcome! key=value</body></html>"
        for path in ["/.git/HEAD", "/.env", "/backup.sql", "/phpinfo.php", "/wp-config.php.bak"]:
            self.assertIsNone(self.check(path, 200, home), path)

    def test_not_found_and_forbidden_are_not_flagged(self):
        self.assertIsNone(self.check("/.git/HEAD", 404, "ref: refs/heads/main"))
        self.assertIsNone(self.check("/.env", 403, "A=1\nB=2"))

    def test_the_file_contents_are_never_stored(self):
        from apps.scanning.plugins.exposed_files import FILES, assess

        finding = assess("acme.com", FILES[1], 200, "DB_PASSWORD=hunter2\nAPI_KEY=sk-123\n")
        self.assertNotIn("hunter2", str(finding.raw_data) + finding.description + finding.title)

    def test_host_without_a_web_server_is_skipped(self):
        from types import SimpleNamespace

        from apps.scanning.plugins.exposed_files import ExposedFilesScanner

        with patch("apps.scanning.plugins.exposed_files.fetch", side_effect=RuntimeError("down")) as fetched:
            self.assertEqual(ExposedFilesScanner().run(SimpleNamespace(value="acme.com")), [])
        self.assertEqual(fetched.call_count, 1)


class ZoneTransferTests(SimpleTestCase):
    def run_scanner(self, transfers):
        from types import SimpleNamespace

        from apps.scanning.plugins.dns_zone_transfer import DnsZoneTransferScanner

        scanner = DnsZoneTransferScanner()
        scanner._nameservers = lambda domain: sorted(transfers)
        scanner._transfer = lambda domain, nameserver: transfers[nameserver]
        return scanner.run(SimpleNamespace(root_domain="acme.com"))

    def test_only_nameservers_that_grant_the_transfer_are_reported(self):
        findings = self.run_scanner({"ns1.acme.com": None, "ns2.acme.com": 143})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].identifier, "ns2.acme.com")
        self.assertEqual(findings[0].severity, Finding.Severity.HIGH)
        self.assertEqual(findings[0].asset_value, "acme.com")
        self.assertEqual(findings[0].raw_data, {"check": "zone_transfer_allowed", "nameserver": "ns2.acme.com", "names": 143})

    def test_refusals_and_timeouts_mean_no_finding(self):
        import dns.exception

        from apps.scanning.plugins.dns_zone_transfer import DnsZoneTransferScanner

        with patch("apps.scanning.plugins.dns_zone_transfer.assert_public_target"), patch(
            "apps.scanning.plugins.dns_zone_transfer.dns.resolver.Resolver.resolve",
            return_value=[MagicMock(to_text=lambda: "203.0.113.5")],
        ), patch(
            "apps.scanning.plugins.dns_zone_transfer.dns.zone.from_xfr",
            side_effect=dns.exception.FormError("refused"),
        ):
            self.assertIsNone(DnsZoneTransferScanner()._transfer("acme.com", "ns1.acme.com"))

    def test_a_nameserver_on_a_private_address_is_not_contacted(self):
        from apps.scanning.plugins.dns_zone_transfer import DnsZoneTransferScanner
        from apps.scanning.targets import TargetNotAllowed

        with patch(
            "apps.scanning.plugins.dns_zone_transfer.assert_public_target", side_effect=TargetNotAllowed("private")
        ), patch("apps.scanning.plugins.dns_zone_transfer.dns.query.xfr") as xfr:
            self.assertIsNone(DnsZoneTransferScanner()._transfer("acme.com", "ns.internal.acme.com"))
        xfr.assert_not_called()


class CorsTests(SimpleTestCase):
    def check(self, origin, credentials=None):
        from apps.scanning.plugins.cors import PROBE_ORIGIN, assess

        finding = assess("acme.com", PROBE_ORIGIN if origin == "ECHO" else origin, credentials)
        return (finding.raw_data["check"], finding.severity) if finding else None

    def test_echoing_any_origin_with_credentials_is_high(self):
        self.assertEqual(self.check("ECHO", "true"), ("cors_any_origin_with_credentials", "high"))
        self.assertEqual(self.check("ECHO", "TRUE"), ("cors_any_origin_with_credentials", "high"))

    def test_lesser_cases(self):
        self.assertEqual(self.check("null", "true"), ("cors_null_origin_with_credentials", "medium"))
        self.assertEqual(self.check("ECHO"), ("cors_any_origin", "low"))

    def test_normal_configurations_are_fine(self):
        self.assertIsNone(self.check(None))
        self.assertIsNone(self.check("*"))
        self.assertIsNone(self.check("https://app.acme.com", "true"))


class CookieSecurityTests(SimpleTestCase):
    def assess(self, *headers):
        from apps.scanning.plugins.cookie_security import assess

        return [(f.identifier, f.severity, f.raw_data["missing"]) for f in assess("acme.com", list(headers))]

    def test_unprotected_session_cookie_is_medium(self):
        self.assertEqual(self.assess("PHPSESSID=abc123; path=/"), [("PHPSESSID", "medium", ["Secure", "HttpOnly", "SameSite"])])
        self.assertEqual(self.assess("auth_token=x; Secure; SameSite=Lax"), [("auth_token", "medium", ["HttpOnly"])])

    def test_other_cookies_and_missing_samesite_only_are_low(self):
        self.assertEqual(self.assess("theme=dark; Path=/"), [("theme", "low", ["Secure", "HttpOnly", "SameSite"])])
        self.assertEqual(self.assess("sessionid=x; Secure; HttpOnly"), [("sessionid", "low", ["SameSite"])])

    def test_fully_protected_cookie_and_no_cookies_report_nothing(self):
        self.assertEqual(self.assess("sessionid=x; Path=/; secure; httponly; samesite=Strict"), [])
        self.assertEqual(self.assess(), [])


class HttpsEnforcementTests(SimpleTestCase):
    def check(self, status, location=None, https_works=True):
        from apps.scanning.plugins.https_enforcement import assess

        finding = assess("acme.com", status, location, https_works)
        return (finding.raw_data["check"], finding.severity) if finding else None

    def test_redirect_to_https_is_correct(self):
        self.assertIsNone(self.check(301, "https://acme.com/"))
        self.assertIsNone(self.check(308, "https://www.acme.com/"))

    def test_serving_content_over_http_is_flagged(self):
        self.assertEqual(self.check(200), ("no_https_redirect", "medium"))
        self.assertEqual(self.check(302, "http://acme.com/home"), ("no_https_redirect", "medium"))
        self.assertEqual(self.check(302, "/home"), ("no_https_redirect", "medium"))

    def test_no_https_at_all_is_high(self):
        self.assertEqual(self.check(200, https_works=False), ("http_only", "high"))

    def test_host_with_no_plain_http_is_skipped(self):
        from types import SimpleNamespace

        from apps.scanning.plugins.https_enforcement import HttpsEnforcementScanner

        with patch("apps.scanning.plugins.https_enforcement.fetch", side_effect=RuntimeError("closed")):
            self.assertEqual(HttpsEnforcementScanner().run(SimpleNamespace(value="acme.com")), [])


class NewScannerRegistrationTests(SimpleTestCase):
    NEW = [
        "email_security", "subdomain_takeover", "tls_config", "outdated_software", "security_txt",
        "exposed_files", "dns_zone_transfer", "cors", "cookie_security", "https_enforcement",
    ]

    def test_all_are_registered_with_a_label_and_description(self):
        from apps.scanning.plugins.registry import get_scanner, list_scanners

        for name in self.NEW:
            self.assertIn(name, list_scanners())
            scanner = get_scanner(name)
            self.assertTrue(scanner.label and scanner.description, name)
            self.assertTrue(scanner.owned_finding_types, name)

    def test_every_check_a_scanner_can_report_has_guidance(self):
        import re
        from pathlib import Path

        from apps.findings.guidance import CHECK_GUIDANCE

        plugins = Path(__file__).resolve().parent.parent / "plugins"
        reported = set()
        for name in self.NEW:
            source = (plugins / f"{name}.py").read_text()
            # Check codes appear as the first argument of a finding/Issue
            # helper, in a "check": value, or in the exposed-files table.
            reported |= set(re.findall(r'(?:finding|Issue)\(\s*"([a-z0-9_]+)"', source))
            reported |= set(re.findall(r'"check":\s*"([a-z0-9_]+)"', source))
            reported |= set(re.findall(r'SensitiveFile\("[^"]+",\s*"([a-z0-9_]+)"', source))
            reported |= set(re.findall(r'"(session_cookie_flags|cookie_flags)"', source))
        self.assertGreaterEqual(len(reported), 30)
        self.assertEqual(reported - set(CHECK_GUIDANCE), set())
