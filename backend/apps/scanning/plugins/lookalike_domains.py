"""
Has someone registered a domain that looks like ours?

Phishing and invoice fraud usually start with a lookalike domain:
acme-retail.com becomes acmeretail.com, acme-retaii.com or
acme-retail-login.com, and mail from it looks right at a glance. This
generates the usual variations of the organization's domain (the same
techniques as dnstwist: missing, doubled, swapped and look-alike
characters, hyphens, other endings) and reports the ones that exist.

DNS lookups only. Nothing connects to the lookalike domains, which
belong to someone else.

Organization-level: findings are filed on the root domain's asset.
"""

import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import dns.exception
import dns.resolver

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner

# Two-label endings that are sold like a top-level domain.
SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.nz", "co.za", "co.ke", "or.ke",
    "com.br", "co.jp", "co.in", "com.ng", "com.sg", "com.mx", "co.tz", "co.ug",
}
OTHER_ENDINGS = ["com", "net", "org", "co", "io", "info", "biz", "online", "shop", "app", "site", "xyz"]
# Words fraudsters add to make a domain look official.
ADDED_WORDS = ["login", "secure", "support", "account", "pay", "billing", "verify", "online"]
HOMOGLYPHS = {
    "o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"], "e": ["3"],
    "s": ["5"], "g": ["q"], "q": ["g"], "m": ["rn"], "w": ["vv"], "d": ["cl"], "a": ["4"],
}
MULTI_HOMOGLYPHS = {"rn": "m", "vv": "w", "cl": "d"}
KEYBOARD_NEIGHBOURS = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok",
    "o": "ipl", "p": "ol", "a": "qsz", "s": "adw", "d": "sfe", "f": "dgr", "g": "fht", "h": "gjy",
    "j": "hku", "k": "jli", "l": "ko", "z": "ax", "x": "zc", "c": "xv", "v": "cb", "b": "vn",
    "n": "bm", "m": "n",
}
VOWELS = "aeiou"
ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def split_domain(domain: str) -> tuple[str, str]:
    """("acme-retail", "co.uk") for "acme-retail.co.uk"; a subdomain's own labels are dropped."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    return labels[-2], labels[-1]


def _valid_label(label: str) -> bool:
    return (
        0 < len(label) <= 63 and set(label) <= ALLOWED
        and not label.startswith("-") and not label.endswith("-") and "--" not in label
    )


def permutations(domain: str) -> dict[str, str]:
    """Every lookalike of `domain` worth checking, mapped to how it was made."""
    name, suffix = split_domain(domain)
    variants: dict[str, str] = {}

    def add(label: str, technique: str, ending: str = suffix):
        candidate = f"{label}.{ending}"
        if _valid_label(label) and candidate != f"{name}.{suffix}" and candidate not in variants:
            variants[candidate] = technique

    for i, char in enumerate(name):
        if char != "-":
            add(name[:i] + name[i + 1:], "missing letter")
        add(name[:i] + char + name[i:], "doubled letter")
        if i < len(name) - 1:
            add(name[:i] + name[i + 1] + char + name[i + 2:], "swapped letters")
        for glyph in HOMOGLYPHS.get(char, []):
            add(name[:i] + glyph + name[i + 1:], "look-alike character")
        for neighbour in KEYBOARD_NEIGHBOURS.get(char, ""):
            add(name[:i] + neighbour + name[i + 1:], "keyboard typo")
        if char in VOWELS:
            for vowel in VOWELS:
                if vowel != char:
                    add(name[:i] + vowel + name[i + 1:], "different vowel")
        if 0 < i and name[i - 1] != "-" and char != "-":
            add(name[:i] + "-" + name[i:], "added hyphen")
    for pair, glyph in MULTI_HOMOGLYPHS.items():
        if pair in name:
            add(name.replace(pair, glyph), "look-alike character")
    if "-" in name:
        add(name.replace("-", ""), "hyphen removed")
    for word in ADDED_WORDS:
        add(f"{name}-{word}", "added word")
        add(f"{word}-{name}", "added word")
    for ending in OTHER_ENDINGS:
        if ending != suffix:
            add(name, "different ending", ending)
    return variants


@dataclass
class Registration:
    domain: str
    addresses: list[str]
    mail_servers: list[str]


@register_scanner
class LookalikeDomainScanner(BaseScanner):
    name = "lookalike_domains"
    category = "email_domain"
    label = "Lookalike domains"
    description = (
        "Looks for registered domains that imitate yours (typos, look-alike characters, other "
        "endings) and could be used for phishing."
    )
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.LOOKALIKE_DOMAIN]

    TIMEOUT_SECONDS = 3
    WORKERS = 24
    MAX_CANDIDATES = 400

    def run(self, target) -> list[RawFinding]:
        domain = target.root_domain
        candidates = dict(list(permutations(domain).items())[: self.MAX_CANDIDATES])
        # Some endings answer for every name (wildcard DNS); a lookalike
        # there proves nothing, so those endings are left out.
        wildcard_endings = {
            ending for ending in {c.split(".", 1)[1] for c in candidates}
            if self._lookup(f"sentinel-{secrets.token_hex(6)}.{ending}").addresses
        }
        candidates = {c: t for c, t in candidates.items() if c.split(".", 1)[1] not in wildcard_endings}

        with ThreadPoolExecutor(max_workers=self.WORKERS) as pool:
            registrations = list(pool.map(self._lookup, candidates))

        findings = []
        for registration in registrations:
            if not registration.addresses and not registration.mail_servers:
                continue
            can_mail = bool(registration.mail_servers)
            findings.append(RawFinding(
                finding_type=Finding.FindingType.LOOKALIKE_DOMAIN,
                identifier=registration.domain,
                severity=Finding.Severity.MEDIUM if can_mail else Finding.Severity.LOW,
                title=f"Lookalike domain registered: {registration.domain}",
                description=(
                    f"{registration.domain} imitates {domain} ({candidates[registration.domain]}) and "
                    + ("can send and receive email." if can_mail else "points to a server.")
                    + " If your organization registered it, mark this as an accepted risk."
                ),
                raw_data={
                    "check": "lookalike_mail" if can_mail else "lookalike_web",
                    "domain": registration.domain,
                    "technique": candidates[registration.domain],
                    "addresses": registration.addresses,
                    "mail_servers": registration.mail_servers,
                },
                asset_value=domain,
            ))
        return findings

    def _lookup(self, name: str) -> Registration:
        return Registration(name, self._records(name, "A"), self._records(name, "MX"))

    def _records(self, name: str, record_type: str) -> list[str]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = self.TIMEOUT_SECONDS
        try:
            answers = resolver.resolve(name, record_type)
        except dns.exception.DNSException:
            # Unregistered, no such record, or no answer in time: either
            # way nothing here to report.
            return []
        if record_type == "MX":
            return sorted(str(answer.exchange).rstrip(".") for answer in answers)
        return sorted(answer.to_text() for answer in answers)
