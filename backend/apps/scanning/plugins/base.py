"""
The plugin contract every scanner implements.

Adding a new scanner (nmap, nuclei, httpx, subfinder, ...) means writing
one new file that subclasses BaseScanner and registering it -- nothing
in tasks.py, models.py, or the orchestration layer ever changes. That's
the whole point of this interface: core code is closed for
modification, open for extension.
"""

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class RawFinding:
    """
    What a scanner hands back for one discovered issue. The task layer
    turns this into a persisted Finding row -- the scanner itself never
    touches the database directly, which keeps plugins trivially
    testable (pure function in, list of RawFinding out).

    asset_value is only used by organization-level scanners (e.g.
    subfinder): it names the (possibly brand-new) Asset this finding
    belongs to. Asset-level scanners leave it None -- the task layer
    already knows the target asset from the ScanJob itself.
    """

    finding_type: str          # one of Finding.FindingType values
    identifier: str            # what makes this finding unique within the asset,
                                # e.g. "443", "missing:Strict-Transport-Security"
    severity: str               # one of Finding.Severity values
    title: str
    description: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    asset_value: str | None = None


@dataclass
class RawTechnology:
    """
    A detected technology, handed back by scanners that implement
    extract_technologies() (currently just httpx). Turned into a
    Technology row by the task layer, same pattern as RawFinding.
    """

    name: str
    version: str = ""
    category: str = ""


class BaseScanner(ABC):
    """
    Subclass this and set the class attributes below.

    - name: matches ScanJob.scanner_name, e.g. "ssl_expiry", "nmap"
    - label / description: human-readable name and one-line summary,
      shown on the Scanners page
    - applies_to: whether this scanner targets a single Asset or a
      whole Organization (subdomain discovery is org-level; port
      scanning is asset-level)
    - owned_finding_types: the Finding.FindingType values this scanner
      is authoritative for. The task layer uses this to resolve
      findings that stop appearing between runs (e.g. a port that
      closed) WITHOUT accidentally resolving findings that belong to a
      different scanner on the same asset.
    """

    name: str
    # What people see in the UI instead of the internal name. Optional:
    # a plugin that sets neither still works and shows up as `name`.
    label: str = ""
    description: str = ""
    # Groups scanners on the Scanners page: discovery, network, web,
    # encryption or email_domain.
    category: str = "web"
    applies_to: Literal["asset", "organization"] = "asset"
    owned_finding_types: list[str] = []
    # Asset-level scanners that connect to the host can't do anything
    # with a name that doesn't resolve: the job is skipped instead of
    # failing three times. DNS-only scanners (where "doesn't resolve"
    # is itself the answer) set this to False.
    needs_address: bool = True
    # Programs that must be installed on the worker, checked before a scan.
    requires_tools: list[str] = []

    @abstractmethod
    def run(self, target) -> list[RawFinding]:
        """
        `target` is an Asset instance (if applies_to == "asset") or an
        Organization instance (if applies_to == "organization").
        Must return a list of RawFinding -- never raise for "no
        findings", just return an empty list. Raise only for genuine
        scan failure (target unreachable, tool crashed, etc.) so the
        task layer can mark the ScanJob failed and retry.
        """
        raise NotImplementedError
    
    def extract_technologies(self, target) -> list[RawTechnology]:
        """
        Optional. Override only in scanners that fingerprint tech stack
        (currently httpx). Default: no technologies detected. Only
        called by the task layer for applies_to == "asset" scanners.
        """
        return []

    def extract_asset_facts(self, target) -> dict:
        """
        Optional. What this scanner learned about the host itself rather
        than an issue on it -- e.g. {"web": {"status": 200, ...}} from
        httpx, {"hosting": {"ips": [...]}} from dns_monitor. Merged into
        the Asset's field of the same name by the task layer. Only called
        after a successful run of an applies_to == "asset" scanner.
        """
        return {}

    def missing_tools(self) -> list[str]:
        """The required programs the worker doesn't have; an empty list when it can run."""
        return [tool for tool in self.requires_tools if shutil.which(tool) is None]
