"""
Port scanner using nmap as a subprocess, parsed from its XML output
(-oX -) rather than screen-scraping human-readable text -- XML is
stable across nmap versions, plain text isn't.

Uses -sT (TCP connect scan) rather than -sS (SYN scan) because SYN
scans require raw-socket privileges (CAP_NET_RAW / root) that the
worker container shouldn't need to run as. Slightly slower, but works
in an unprivileged container -- a deliberate trade-off worth stating
if asked about it.
"""

import subprocess
import xml.etree.ElementTree as ET

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

# Top ~100 common ports rather than a full 1-65535 sweep -- keeps scan
# time reasonable for a portfolio/demo context. Swap for --top-ports N
# or a custom range once this needs to be production-thorough.
DEFAULT_PORT_RANGE = "21-23,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,6379,8000,8080,8443"


@register_scanner
class NmapScanner(BaseScanner):
    name = "nmap"
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.OPEN_PORT]

    TIMEOUT_SECONDS = 120

    def run(self, target) -> list[RawFinding]:
        host = target.value
        xml_output = self._run_nmap(host)
        return self._parse(xml_output)

    def _run_nmap(self, host: str) -> str:
        cmd = [
            "nmap",
            "-sT",              # TCP connect scan, no raw-socket privileges needed
            "-Pn",              # skip host-discovery ping (many hosts block ICMP)
            "-p", DEFAULT_PORT_RANGE,
            "-oX", "-",         # XML to stdout
            "--host-timeout", "60s",
            host,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT_SECONDS,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"nmap scan of {host} timed out after {self.TIMEOUT_SECONDS}s") from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"nmap scan of {host} failed: {exc.stderr}") from exc
        return result.stdout

    def _parse(self, xml_output: str) -> list[RawFinding]:
        root = ET.fromstring(xml_output)
        findings = []

        for port_el in root.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_number = port_el.get("portid")
            protocol = port_el.get("protocol", "tcp")

            service_el = port_el.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""

            description = f"Port {port_number}/{protocol} is open, service: {service_name}"
            if product:
                description += f" ({product})"

            findings.append(
                RawFinding(
                    finding_type=Finding.FindingType.OPEN_PORT,
                    identifier=f"{port_number}/{protocol}",
                    severity=self._severity_for(port_number, service_name),
                    title=f"Open port {port_number}/{protocol} ({service_name})",
                    description=description,
                    raw_data={
                        "port": port_number,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                    },
                )
            )
        return findings

    # Ports that are commonly misconfigured/high-risk when exposed get
    # flagged higher than routine web ports. Deliberately simple and
    # documented -- see the risk-score module for where this feeds in.
    HIGH_RISK_PORTS = {"3389", "3306", "5432", "6379", "23"}

    @classmethod
    def _severity_for(cls, port: str, service_name: str) -> str:
        if port in cls.HIGH_RISK_PORTS:
            return Finding.Severity.HIGH
        if port in {"80", "443", "8080", "8443"}:
            return Finding.Severity.INFO
        return Finding.Severity.LOW