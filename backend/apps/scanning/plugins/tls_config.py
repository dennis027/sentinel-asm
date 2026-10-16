"""
How well is the HTTPS endpoint configured -- beyond "has the certificate
expired", which ssl_expiry covers.

Uses Python's own TLS stack: one handshake per protocol version to see
what the server accepts, and one verifying handshake to see whether a
browser would trust the certificate. No external binary.

What it does not do: enumerate individual cipher suites. A dedicated
tool (sslyze, testssl.sh) is the upgrade path if that depth is needed.
"""

import socket
import ssl

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

# Deprecated by RFC 8996 (2021); browsers no longer connect with them.
OLD_VERSIONS = [(ssl.TLSVersion.TLSv1, "TLS 1.0"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1")]
MODERN_VERSIONS = [(ssl.TLSVersion.TLSv1_2, "TLS 1.2"), (ssl.TLSVersion.TLSv1_3, "TLS 1.3")]


def findings_for(host: str, accepted: set[str], trust_error: str | None) -> list[RawFinding]:
    """Turns the probe results into findings. Pure function."""

    def finding(check: str, severity: str, title: str, description: str, **raw) -> RawFinding:
        return RawFinding(
            finding_type=Finding.FindingType.WEAK_TLS,
            identifier=check,
            severity=severity,
            title=title,
            description=description,
            raw_data={"check": check, "accepted_versions": sorted(accepted), **raw},
        )

    results = []
    old = [name for _, name in OLD_VERSIONS if name in accepted]
    if old:
        results.append(finding(
            "old_protocol", Finding.Severity.MEDIUM, f"Server still accepts {' and '.join(old)}",
            f"{host} accepts connections using {' and '.join(old)}, which were retired in 2021 "
            "because of known weaknesses.",
        ))
    if not accepted & {"TLS 1.2", "TLS 1.3"}:
        results.append(finding(
            "no_modern_protocol", Finding.Severity.HIGH, "Server does not support TLS 1.2 or 1.3",
            f"{host} only offers retired TLS versions. Current browsers refuse to connect to it.",
        ))
    elif "TLS 1.3" not in accepted:
        results.append(finding(
            "no_tls13", Finding.Severity.INFO, "Server does not support TLS 1.3",
            f"{host} supports TLS 1.2 but not TLS 1.3, the current version.",
        ))
    if trust_error:
        results.append(finding(
            "untrusted_certificate", Finding.Severity.HIGH, "Certificate is not trusted by browsers",
            f"A browser connecting to {host} would show a security warning: {trust_error}.",
            trust_error=trust_error,
        ))
    return results


@register_scanner
class TlsConfigScanner(BaseScanner):
    name = "tls_config"
    category = "encryption"
    label = "TLS configuration"
    description = (
        "Checks which TLS versions the site accepts and whether browsers trust its certificate."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.WEAK_TLS]

    PORT = 443
    TIMEOUT_SECONDS = 6

    def run(self, target) -> list[RawFinding]:
        host = target.value
        try:
            socket.create_connection((host, self.PORT), timeout=self.TIMEOUT_SECONDS).close()
        except OSError:
            # Nothing listening on 443: this host has no TLS to grade.
            return []

        accepted = {name for version, name in OLD_VERSIONS + MODERN_VERSIONS if self._accepts(host, version)}
        if not accepted:
            # The port answered but no handshake of any version worked
            # -- it is not serving TLS (or not to us).
            return []
        return findings_for(host, accepted, self._trust_error(host))

    def _accepts(self, host: str, version: ssl.TLSVersion) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            # Offering a retired version at all needs the library's own
            # safety floor lowered -- for this one probe only.
            context.set_ciphers("ALL:@SECLEVEL=0")
            context.minimum_version = version
            context.maximum_version = version
        except (ssl.SSLError, ValueError):
            return False  # this Python build can't speak that version
        try:
            with socket.create_connection((host, self.PORT), timeout=self.TIMEOUT_SECONDS) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return True
        except (ssl.SSLError, OSError):
            return False

    def _trust_error(self, host: str) -> str | None:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, self.PORT), timeout=self.TIMEOUT_SECONDS) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return None
        except ssl.SSLCertVerificationError as exc:
            return exc.verify_message or "certificate verification failed"
        except (ssl.SSLError, OSError):
            # Couldn't complete a default handshake for some other
            # reason (e.g. only retired versions) -- reported above.
            return None
