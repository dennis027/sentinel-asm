"""
Vulnerability/misconfiguration scanning via nuclei (ProjectDiscovery),
using the full community template set -- no tag/severity restriction.

IMPORTANT: this runs the complete nuclei template library, including
active-detection templates, against the target. Only scan assets you
have authorization to test. This scanner is intentionally unrestricted
per a deliberate choice made for this project -- see README for the
reasoning and how to narrow scope (-tags/-severity) if that changes.
"""

import json
import subprocess

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

# nuclei's own severity scale already matches Finding.Severity almost
# exactly -- "unknown" is nuclei's rare catch-all for templates with no
# declared severity, mapped to INFO rather than dropped.
NUCLEI_SEVERITY_MAP = {
    "info": Finding.Severity.INFO,
    "low": Finding.Severity.LOW,
    "medium": Finding.Severity.MEDIUM,
    "high": Finding.Severity.HIGH,
    "critical": Finding.Severity.CRITICAL,
    "unknown": Finding.Severity.INFO,
}


@register_scanner
class NucleiScanner(BaseScanner):
    name = "nuclei"
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.NUCLEI_MATCH]

    TEMPLATES_DIR = "/opt/nuclei-templates"
    TIMEOUT_SECONDS = 600  # full template set against one host is slow

    def run(self, target) -> list[RawFinding]:
        jsonl_output = self._run_nuclei(target.value)
        return self._parse(jsonl_output)

    def _run_nuclei(self, host: str) -> str:
        cmd = [
            "nuclei",
            "-u", f"https://{host}",
            "-t", self.TEMPLATES_DIR,
            "-jsonl",
            "-silent",
            "-duc",              # skip nuclei's own update-check API calls
            "-sr",                # fall back to system DNS resolver
            "-timeout", "10",     # per-request timeout, seconds
            "-rate-limit", "50",  # requests/sec -- polite default, not a stealth scanner
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT_SECONDS,
                # nuclei exits non-zero in some no-match scenarios --
                # don't use check=True, just read stdout regardless.
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"nuclei scan of {host} timed out after {self.TIMEOUT_SECONDS}s"
            ) from exc
        return result.stdout

    def _parse(self, jsonl_output: str) -> list[RawFinding]:
        findings = []
        for line in jsonl_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                match = json.loads(line)
            except json.JSONDecodeError:
                # A single malformed line shouldn't sink an otherwise
                # valid scan -- skip it, keep parsing the rest.
                continue

            template_id = match.get("template-id", "unknown-template")
            info = match.get("info", {})
            severity = NUCLEI_SEVERITY_MAP.get(
                info.get("severity", "unknown"), Finding.Severity.INFO
            )
            name = info.get("name", template_id)
            matched_at = match.get("matched-at", "")

            findings.append(
                RawFinding(
                    finding_type=Finding.FindingType.NUCLEI_MATCH,
                    # template-id is already unique per distinct check;
                    # matched-at disambiguates the (rare) case where one
                    # template fires more than once on different endpoints.
                    identifier=f"{template_id}:{matched_at}",
                    severity=severity,
                    title=name,
                    description=info.get("description", "") or f"nuclei template '{template_id}' matched.",
                    raw_data={
                        "template_id": template_id,
                        "matched_at": matched_at,
                        "tags": info.get("tags", []),
                        "reference": info.get("reference", []),
                    },
                )
            )
        return findings