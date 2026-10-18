"""
Public cloud storage named after the organization.

Amazon S3 and Google Cloud Storage bucket names are global, and teams
name them predictably: `acme-backups`, `acme-assets`, `acme-prod`. A
bucket left listable lets anyone see, and usually download, every file
in it -- one of the most common causes of large data leaks.

Tries a few dozen likely names on both services with one anonymous
request each (the same one a browser would make) and reports buckets
whose contents anyone can list. It reads the listing only, never a
file. A bucket that exists but is private is not reported. Because
anyone can create a bucket with any free name, the finding asks the
team to confirm it is theirs.
"""

import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

S = Finding.Severity
SUFFIXES = ["", "backup", "backups", "assets", "static", "media", "uploads", "files", "data", "logs", "dev",
            "staging", "prod", "public", "images", "cdn", "web", "archive", "db"]
PROVIDERS = {
    "s3": ("Amazon S3", lambda name: (f"{name}.s3.amazonaws.com", "/?max-keys=20")),
    "gcs": ("Google Cloud Storage", lambda name: ("storage.googleapis.com", f"/{name}?max-keys=20")),
}
BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")


def candidate_names(root_domain: str, organization_name: str = "") -> list[str]:
    """acme-retail.example, "Acme Retail" -> acme-retail, acme-retail-backups, acmeretail, acmeretail-backups..."""
    label = root_domain.split(".")[0].lower()
    slug = re.sub(r"[^a-z0-9]+", "-", organization_name.lower()).strip("-")
    bases = []
    for base in (label, label.replace("-", ""), slug, slug.replace("-", "")):
        if base and base not in bases:
            bases.append(base)
    names = []
    for base in bases:
        for suffix in SUFFIXES:
            name = f"{base}-{suffix}" if suffix else base
            if BUCKET_NAME.match(name) and name not in names:
                names.append(name)
    return names


def listing(body: str) -> tuple[bool, list[str]]:
    """(is this an object listing, a few object names from it)."""
    if "<ListBucketResult" not in body:
        return False, []
    return True, re.findall(r"<Key>([^<]{1,200})</Key>", body)[:5]


@register_scanner
class CloudStorageScanner(BaseScanner):
    name = "cloud_storage"
    category = "discovery"
    label = "Public cloud storage"
    description = (
        "Looks for Amazon S3 and Google Cloud Storage buckets named after your company whose contents anyone "
        "can list."
    )
    applies_to = "organization"
    owned_finding_types = [Finding.FindingType.PUBLIC_BUCKET]

    TIMEOUT = 8

    def run(self, target) -> list[RawFinding]:
        domain = target.root_domain
        checks = [(provider, name) for name in candidate_names(domain, target.name) for provider in PROVIDERS]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda check: self._check(*check), checks))
        if checks and all(result is None for result in results):
            # Every request failed: no network, not "no buckets".
            raise RuntimeError("Could not reach Amazon S3 or Google Cloud Storage.")

        findings = []
        for (provider, name), result in zip(checks, results):
            if not result or not result[0]:
                continue
            _, objects, url = result
            service = PROVIDERS[provider][0]
            sample = ", ".join(objects[:5]) or "it is empty right now"
            findings.append(RawFinding(
                finding_type=Finding.FindingType.PUBLIC_BUCKET, identifier=f"{provider}:{name}",
                severity=S.HIGH if objects else S.MEDIUM,
                title=f"Public {service} bucket: {name}",
                description=(
                    f"Anyone can list the files in the {service} bucket \"{name}\" ({url}). Files listed: {sample}. "
                    "Confirm it belongs to you; if it does, block public access unless it only holds files meant "
                    "for the public website."
                ),
                raw_data={"check": "public_bucket", "provider": provider, "bucket": name, "url": url,
                          "sample_objects": objects[:5]},
                asset_value=domain,
            ))
        return findings

    def _check(self, provider: str, name: str):
        """(listable, sample objects, url), (False, [], url) for no or private bucket, None if unreachable."""
        host, path = PROVIDERS[provider][1](name)
        try:
            page = fetch(host, path, timeout=self.TIMEOUT, schemes=("https",), follow_redirects=False)
            if page.status in (301, 307) and provider == "s3":
                # A bucket in another region: S3 names the endpoint to use.
                location = page.headers.get("Location") or ""
                endpoint = re.search(r"<Endpoint>([^<]+)</Endpoint>", page.body)
                redirect_host = urlsplit(location).hostname if location else (endpoint.group(1) if endpoint else "")
                if redirect_host and redirect_host.endswith(".amazonaws.com"):
                    host = redirect_host
                    page = fetch(host, path, timeout=self.TIMEOUT, schemes=("https",), follow_redirects=False)
        except RuntimeError:
            return None
        url = f"https://{host}{path.split('?')[0]}"
        if page.status != 200:
            return False, [], url
        listable, objects = listing(page.body)
        return listable, objects, url
