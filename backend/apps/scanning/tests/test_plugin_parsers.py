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