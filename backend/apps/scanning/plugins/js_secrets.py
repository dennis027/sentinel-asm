"""
Secrets in the JavaScript a site sends to every visitor.

Front-end code is public: anyone can open it in the browser. Build
tools make it easy to bundle a server-side key by mistake (a `.env`
variable used in the wrong place), and then the key is in every
visitor's browser. Bug bounty hunters and attackers search bundles for
exactly this.

Reads the home page, its inline scripts and the scripts it loads from
the same site or the organization's own domain (never third-party
CDNs), and looks for key formats that are distinctive enough not to be
guessed at: a Stripe secret key, a GitHub token, an AWS access key, a
private key block... Publishable keys that are meant to be public
(Stripe `pk_live_`, Firebase config) are ignored. The finding shows the
key masked; the full value is never stored.
"""

import hashlib
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

S = Finding.Severity
MAX_SCRIPTS = 20
MAX_SCRIPT_BYTES = 3 * 1024 * 1024


@dataclass
class SecretKind:
    kind: str
    name: str
    pattern: re.Pattern
    severity: str
    advice: str


KINDS = [
    SecretKind("private_key", "Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
               S.CRITICAL, "Replace the key pair and anything it signed or decrypted."),
    SecretKind("aws_access_key", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), S.HIGH,
               "Deactivate the key in AWS IAM and check CloudTrail for its use."),
    SecretKind("stripe_secret", "Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"), S.CRITICAL,
               "Roll the key in the Stripe dashboard; it can create charges and refunds."),
    SecretKind("github_token", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
               S.CRITICAL, "Revoke the token in GitHub; it may give access to private code."),
    SecretKind("slack_token", "Slack token", re.compile(r"\bxox[abpr]-[0-9A-Za-z-]{20,}\b"), S.HIGH,
               "Revoke it in the Slack app settings."),
    SecretKind("slack_webhook", "Slack webhook", re.compile(
        r"https://hooks\.slack\.com/services/T[0-9A-Z]{6,}/B[0-9A-Z]{6,}/[0-9A-Za-z]{20,}"), S.MEDIUM,
               "Regenerate the webhook; anyone with it can post into your Slack."),
    SecretKind("sendgrid_key", "SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b"),
               S.HIGH, "Delete the key in SendGrid; it can send email as you."),
    SecretKind("mailgun_key", "Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b"), S.HIGH,
               "Rotate the key in Mailgun; it can send email as you."),
    SecretKind("openai_key", "OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b"),
               S.HIGH, "Revoke the key at platform.openai.com; others can run up your bill."),
    SecretKind("anthropic_key", "Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b"),
               S.HIGH, "Revoke the key in the Claude Console; others can run up your bill."),
    SecretKind("google_api_key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), S.LOW,
               "Google keys in web pages are often intended (Maps, Firebase); make sure this one is restricted "
               "to your sites and to the APIs it needs."),
]


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources: list[str] = []
        self.inline: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            src = dict(attrs).get("src")
            if src:
                self.sources.append(src)
            else:
                self._in_script = True
                self.inline.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.inline[-1] += data


def mask(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "…"
    return f"{value[:6]}…{value[-4:]}"


def find_secrets(text: str) -> list[tuple[SecretKind, str]]:
    found, seen = [], set()
    for kind in KINDS:
        for match in kind.pattern.finditer(text):
            value = match.group(0)
            # Placeholders from docs and examples.
            if re.search(r"EXAMPLE|XXXX|xxxx|0000000000|your[_-]?key", value):
                continue
            if value not in seen:
                seen.add(value)
                found.append((kind, value))
    return found


def script_urls(page_url: str, html: str, host: str, root_domain: str) -> tuple[list[str], list[str]]:
    """(script URLs on the site or the organization's domain, inline script bodies)."""
    parser = _Scripts()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 - a broken page still has whatever was parsed
        pass
    urls = []
    for src in parser.sources:
        url = urljoin(page_url, src)
        hostname = (urlsplit(url).hostname or "").lower()
        if urlsplit(url).scheme in ("http", "https") and (
            hostname == host or hostname == root_domain or hostname.endswith(f".{root_domain}")
        ) and url not in urls:
            urls.append(url)
    return urls[:MAX_SCRIPTS], [code for code in parser.inline if code.strip()]


@register_scanner
class JsSecretsScanner(BaseScanner):
    name = "js_secrets"
    category = "web"
    label = "Secrets in JavaScript"
    description = (
        "Reads the JavaScript your sites send to every visitor and looks for API keys, tokens and private keys "
        "left in it."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.EXPOSED_SECRET]

    def run(self, target) -> list[RawFinding]:
        host = target.value
        root = target.organization.root_domain if getattr(target, "organization_id", None) else host
        page = fetch(host, "/", max_bytes=1024 * 1024)
        if page.status >= 400 or not page.body:
            return []
        urls, inline = script_urls(page.url, page.body, host, root)
        files = [(f"{page.url} (inline script)", code) for code in inline]
        for url in urls:
            parts = urlsplit(url)
            path = parts.path + (f"?{parts.query}" if parts.query else "")
            try:
                script = fetch(parts.hostname, path or "/", schemes=(parts.scheme,), max_bytes=MAX_SCRIPT_BYTES)
            except RuntimeError:
                continue
            if script.status == 200:
                files.append((url, script.body))

        findings, reported = [], set()
        for where, text in files:
            for kind, value in find_secrets(text):
                digest = hashlib.sha256(value.encode()).hexdigest()[:16]
                if digest in reported:
                    continue
                reported.add(digest)
                file_name = urlsplit(where).path.rsplit("/", 1)[-1] or "home page"
                findings.append(RawFinding(
                    finding_type=Finding.FindingType.EXPOSED_SECRET,
                    identifier=f"{kind.kind}:{digest}",
                    severity=kind.severity,
                    title=f"{kind.name} in public JavaScript ({file_name[:60]})",
                    description=(
                        f"{where} contains what looks like a {kind.name} ({mask(value)}). Anyone visiting the site "
                        f"can read it. {kind.advice} Then remove it from the front-end code and keep it on the server."
                    ),
                    raw_data={"check": "exposed_secret", "kind": kind.kind, "file": where[:500],
                              "masked": mask(value), "sha256_prefix": digest},
                ))
        return findings
