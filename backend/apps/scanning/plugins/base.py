"""
The plugin contract every scanner implements.

Adding a new scanner (nmap, nuclei, httpx, subfinder, ...) means writing
one new file that subclasses BaseScanner and registering it -- nothing
in tasks.py, models.py, or the orchestration layer ever changes. That's
the whole point of this interface: core code is closed for
modification, open for extension.
"""

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


class BaseScanner(ABC):
    """
    Subclass this and set the three class attributes below.

    - name: matches ScanJob.scanner_name, e.g. "ssl_expiry", "nmap"
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
    applies_to: Literal["asset", "organization"] = "asset"
    owned_finding_types: list[str] = []

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