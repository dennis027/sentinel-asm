"""
Certificate transparency: every publicly trusted TLS certificate is
logged in public, append-only logs. Searching them for the domain shows

- hostnames nobody told IT about (each certificate names its hosts);
- who is issuing certificates for the domain, and when -- an issuer the
  organization doesn't use is a sign of shadow IT, or of someone
  obtaining certificates to impersonate it.

Uses crt.sh's public search (no account; it can be slow or busy, so a
failed lookup is retried by the scan rather than read as "no
certificates"). Organization-level: hostnames become assets, and each
recent certificate is recorded on the root domain as inventory.
"""

import json
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

S = Finding.Severity
RECENT_DAYS = 90
MAX_CERTIFICATES = 200


def _date(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _issuer_org(issuer: str) -> str:
    """'C=US, O=Let's Encrypt, CN=R11' -> "Let's Encrypt"."""
    for part in issuer.split(","):
        key, _, value = part.strip().partition("=")
        if key == "O":
            return value.strip().strip('"')
    return issuer.strip()[:80]


def analyse(domain: str, entries: list[dict], now: datetime | None = None) -> list[RawFinding]:
    now = now or datetime.now(timezone.utc)
    findings: list[RawFinding] = []
    hostnames: set[str] = set()
    recent = []
    for entry in entries:
        for name in str(entry.get("name_value", "")).lower().split("\n"):
            name = name.strip().lstrip("*.").rstrip(".")
            if name == domain or name.endswith(f".{domain}"):
                hostnames.add(name)
        issued = _date(entry.get("not_before") or entry.get("entry_timestamp"))
        if issued and issued >= now - timedelta(days=RECENT_DAYS):
            recent.append((issued, entry))

    # Filed on each host, which adds hosts nobody knew about as assets.
    # Its own finding type, so subdomain discovery (which owns its own
    # findings) never "resolves" a host that only certificates revealed.
    for host in sorted(hostnames):
        if host != domain:
            findings.append(RawFinding(
                finding_type=Finding.FindingType.CERT_ISSUED, identifier=f"host:{host}", severity=S.INFO,
                title=f"Named in a certificate: {host}",
                description="This host appears in a publicly logged TLS certificate.",
                raw_data={"subdomain": host, "source": "certificate transparency"}, asset_value=host,
            ))

    issuers = Counter(_issuer_org(str(entry.get("issuer_name", ""))) for _, entry in recent)
    usual = {issuer for issuer, count in issuers.items() if count >= 3}
    seen_ids = set()
    for issued, entry in sorted(recent, key=lambda pair: pair[0], reverse=True)[:MAX_CERTIFICATES]:
        cert_id = str(entry["id"] if entry.get("id") is not None else entry.get("serial_number") or "")
        if not cert_id or cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)
        names = sorted({n.strip() for n in str(entry.get("name_value", "")).split("\n") if n.strip()})
        issuer = _issuer_org(str(entry.get("issuer_name", "")))
        unusual = bool(usual) and issuer not in usual
        findings.append(RawFinding(
            finding_type=Finding.FindingType.CERT_ISSUED, identifier=f"crt:{cert_id}", severity=S.INFO,
            title=f"Certificate issued by {issuer} for {names[0] if names else domain}",
            description=f"Issued {issued.date().isoformat()} for {', '.join(names[:6])}"
                        + (f" and {len(names) - 6} more." if len(names) > 6 else "."),
            raw_data={"crt_id": cert_id, "issuer": issuer, "names": names[:20], "not_before": issued.isoformat(),
                      "unusual_issuer": unusual},
            asset_value=domain,
        ))
        if unusual:
            findings.append(RawFinding(
                finding_type=Finding.FindingType.UNUSUAL_CERT, identifier=f"unusual_issuer:{issuer}", severity=S.MEDIUM,
                title=f"Certificate from an unusual issuer ({issuer}) for {domain}",
                description=f"{issuer} issued a certificate on {issued.date().isoformat()} for {', '.join(names[:4])}; "
                            f"the domain's certificates normally come from {', '.join(sorted(usual))}.",
                raw_data={"check": "unusual_issuer", "issuer": issuer, "names": names[:10], "crt_id": cert_id},
                asset_value=domain,
            ))
    return findings


@register_scanner
class CertTransparencyScanner(BaseScanner):
    name = "cert_transparency"
    category = "discovery"
    label = "Certificate transparency"
    description = (
        "Searches public certificate logs for your domain: finds hostnames from their certificates and flags "
        "certificates from issuers you don't normally use."
    )
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.CERT_ISSUED, Finding.FindingType.UNUSUAL_CERT]

    URL = "https://crt.sh/?q=%25.{domain}&output=json&exclude=expired"
    TIMEOUT = 60

    def run(self, target) -> list[RawFinding]:
        domain = target.root_domain
        request = urllib.request.Request(self.URL.format(domain=domain), headers={"User-Agent": "densight/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=self.TIMEOUT) as response:
                entries = json.loads(response.read(20_000_000) or b"[]")
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Certificate transparency search failed: {exc}") from exc
        return analyse(domain, entries if isinstance(entries, list) else [])
