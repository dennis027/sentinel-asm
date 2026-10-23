"""
Guards on WHAT the platform is allowed to scan. Two layers:

- validate_root_domain(): at organization creation, rejects anything
  that isn't a plausible public DNS name (IPs, single-label hosts like
  "db" or "redis", internal-only suffixes).
- assert_public_target(): at scan time, resolves the host and refuses
  to scan if any address is loopback/private/link-local. Without this
  a tenant could aim nmap or the screenshot scanner at the platform's
  own network (Postgres, Redis, cloud metadata) through a DNS name
  that points inward.
"""

import ipaddress
import re
import socket

from django.conf import settings
from rest_framework import serializers

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,63}}$")

# Suffixes that only ever resolve inside a private network.
INTERNAL_SUFFIXES = ("localhost", "local", "internal", "lan", "home.arpa", "corp", "invalid")


class TargetNotAllowed(Exception):
    """Raised for a target the platform refuses to scan. Not retryable."""


class TargetUnreachable(Exception):
    """The host name doesn't exist in DNS, so there is nothing to connect to. Not retryable."""


# getaddrinfo's answers for "this name definitely doesn't exist" (as
# opposed to "the resolver didn't answer", which is worth retrying).
_NO_SUCH_NAME = {
    getattr(socket, name) for name in ("EAI_NONAME", "EAI_NODATA", "EAI_ADDRFAMILY") if hasattr(socket, name)
}


def validate_root_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if len(domain) > 253 or not _DOMAIN_RE.match(domain):
        raise serializers.ValidationError(
            "Enter a public domain name such as example.com (no scheme, path, port or IP address)."
        )
    if any(domain == suffix or domain.endswith(f".{suffix}") for suffix in INTERNAL_SUFFIXES):
        raise serializers.ValidationError("Internal-only domains can't be scanned.")
    return domain


def assert_public_target(host: str, needs_address: bool = False, raise_unclear: bool = False) -> None:
    """
    Refuses hosts that point inward. With needs_address, also raises
    TargetUnreachable for a name that doesn't exist, for scanners that
    would only fail trying to connect to it. With raise_unclear, a
    resolver error that isn't a clear "no such name" is raised as OSError.
    """
    if settings.ALLOW_PRIVATE_SCAN_TARGETS and not needs_address:
        return

    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            if needs_address and exc.errno in _NO_SUCH_NAME:
                raise TargetUnreachable(f"{host} doesn't resolve in DNS, so there was nothing to connect to.")
            # Otherwise nothing to protect, and the scanner itself
            # decides whether that's a failure (dns_monitor treats
            # NXDOMAIN as a legitimate result).
            if raise_unclear:
                raise
            return
        except OSError:
            if raise_unclear:
                raise
            return
        addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]

    if settings.ALLOW_PRIVATE_SCAN_TARGETS:
        return

    blocked = sorted({str(address) for address in addresses if not address.is_global})
    if blocked:
        raise TargetNotAllowed(
            f"{host} resolves to a non-public address ({', '.join(blocked)}) and can't be scanned."
        )


def classify_host(host: str) -> str:
    """
    What a scan would find before it connects: "ok", "missing" (the name
    doesn't exist), "private" (points inside a private network, so it is
    refused) or "unknown" (the resolver didn't give a clear answer).
    """
    try:
        assert_public_target(host, needs_address=True, raise_unclear=True)
    except TargetUnreachable:
        return "missing"
    except TargetNotAllowed:
        return "private"
    except OSError:
        return "unknown"
    return "ok"
