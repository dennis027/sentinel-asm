"""
Subdomain discovery using the subfinder binary (ProjectDiscovery).

This is the platform's only organization-level scanner so far: it
doesn't produce findings about an existing asset, it *creates* new
Asset rows (one per discovered subdomain) and attaches a
SUBDOMAIN_DISCOVERED finding to each one -- that's what asset_value on
RawFinding is for, see plugins/base.py.
"""

import subprocess

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner


@register_scanner
class SubfinderScanner(BaseScanner):
    name = "subfinder"
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.SUBDOMAIN_DISCOVERED]

    TIMEOUT_SECONDS = 180

    def run(self, target) -> list[RawFinding]:
        root_domain = target.root_domain
        subdomains = self._run_subfinder(root_domain)
        return [self._to_raw_finding(sub) for sub in subdomains]

    def _run_subfinder(self, root_domain: str) -> list[str]:
        cmd = ["subfinder", "-d", root_domain, "-silent"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT_SECONDS,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"subfinder scan of {root_domain} timed out after {self.TIMEOUT_SECONDS}s"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"subfinder scan of {root_domain} failed: {exc.stderr}") from exc

        # -silent gives one subdomain per line, nothing else.
        lines = [line.strip() for line in result.stdout.splitlines()]
        return [line for line in lines if line]

    @staticmethod
    def _to_raw_finding(subdomain: str) -> RawFinding:
        return RawFinding(
            finding_type=Finding.FindingType.SUBDOMAIN_DISCOVERED,
            # Constant identifier: uniqueness already comes from asset_value
            # (each subdomain is its own Asset) -- this just needs to be
            # stable so re-scans upsert the same row instead of duplicating.
            identifier="discovered",
            severity=Finding.Severity.INFO,
            title=f"Subdomain discovered: {subdomain}",
            description=f"{subdomain} was found via passive subdomain enumeration.",
            raw_data={"subdomain": subdomain, "source": "subfinder"},
            asset_value=subdomain,
        )