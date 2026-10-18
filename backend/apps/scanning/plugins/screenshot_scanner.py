"""
Website screenshot capture via Playwright (headless Chromium).

Captures the site's landing page and then the pages it links to on the
same host, up to settings.SCREENSHOT_MAX_PAGES in total -- so a site
shows up as its home page, its login page, its docs, and so on, rather
than as a single image.

Each PNG is stored as screenshots/<asset_id>/... in the default storage
(disk, or R2/S3 when configured; see apps/scanning/screenshot_store.py) and its
relative path is recorded in the Finding's raw_data. The files are
served to the UI by GET /api/findings/{id}/screenshot/ (authenticated
and org-scoped) -- there is deliberately no public URL for them.
Local disk storage for now -- swap for S3-class object storage before
this needs to run across multiple worker replicas that don't share a
filesystem (see README).

One evolving finding per page (the landing page keeps the constant
identifier "latest"; every other page is keyed by its path), so a
re-scan overwrites "what this page looks like now" instead of piling
up history, and a page that is no longer linked gets resolved by the
generic reconciliation in tasks.py. Old image files are intentionally
left on disk until a retention job exists.
"""

from datetime import datetime, timezone
from urllib.parse import urldefrag, urljoin, urlsplit

from django.conf import settings

from apps.findings.models import Finding

from apps.scanning import screenshot_store

from .base import BaseScanner, RawFinding
from .registry import register_scanner

# Links that change state or end the session when followed. The crawl
# only ever issues GET requests, but a GET to /logout still logs out.
SKIPPED_PATH_WORDS = ("logout", "log-out", "signout", "sign-out", "delete", "remove", "unsubscribe")

# Not pages: following these downloads a file instead of rendering one.
SKIPPED_EXTENSIONS = (
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".rar", ".7z", ".exe", ".dmg", ".pkg", ".iso",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".mp4", ".mp3", ".avi", ".mov",
    ".css", ".js", ".json", ".xml", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)


def select_pages(landing_url: str, hrefs: list[str], limit: int) -> list[str]:
    """
    From the links on the landing page, picks up to `limit` further
    pages worth a screenshot: same host, http(s), one per distinct
    path, in the order they appear on the page (which puts the main
    navigation first). Pure function -- no browser involved -- so the
    rules are unit-testable.
    """
    if limit <= 0:
        return []

    landing = urlsplit(landing_url)
    seen_paths = {landing.path.rstrip("/")}
    pages: list[str] = []

    for href in hrefs:
        url, _fragment = urldefrag(urljoin(landing_url, (href or "").strip()))
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or parts.hostname != landing.hostname:
            continue

        path = parts.path.rstrip("/")
        lowered = path.lower()
        if path in seen_paths:
            continue
        if lowered.endswith(SKIPPED_EXTENSIONS) or any(word in lowered for word in SKIPPED_PATH_WORDS):
            continue

        seen_paths.add(path)
        # Query strings are dropped: /search?q=a and /search?q=b are the
        # same page for this purpose.
        pages.append(f"{parts.scheme}://{parts.netloc}{parts.path}")
        if len(pages) >= limit:
            break

    return pages


@register_scanner
class ScreenshotScanner(BaseScanner):
    name = "screenshot"
    category = "discovery"
    label = "Screenshot"
    description = (
        "Captures what the site looks like in a browser: the home page and the pages it links to."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.SCREENSHOT]

    TIMEOUT_MS = 15_000
    VIEWPORT = {"width": 1280, "height": 800}

    def run(self, target) -> list[RawFinding]:
        # Imported lazily so importing this module (which happens for
        # every worker on startup, via plugin auto-discovery) doesn't
        # require the playwright package to be importable in every
        # environment that loads plugins/ -- only when this scanner
        # actually runs.
        from playwright.sync_api import sync_playwright

        host = target.value
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        findings: list[RawFinding] = []
        # Several links often land on the same place (everything
        # redirects to /login); one picture of it is enough.
        captured_urls: set[str] = set()

        def capture(page, identifier: str, requested_url: str) -> None:
            final_url = page.url
            if final_url in captured_urls:
                return
            captured_urls.add(final_url)

            relative_path = screenshot_store.save(
                screenshot_store.path_for(target.id, f"{timestamp}-{len(findings):02d}.png"),
                page.screenshot(full_page=False),
            )
            page_title = page.title()
            findings.append(
                RawFinding(
                    finding_type=Finding.FindingType.SCREENSHOT,
                    identifier=identifier,
                    severity=Finding.Severity.INFO,
                    title=f"Screenshot captured: {page_title or final_url}"[:255],
                    description=f"Visual snapshot of {final_url}.",
                    raw_data={
                        "screenshot_path": relative_path,
                        "page_title": page_title,
                        "page_url": requested_url,
                        "final_url": final_url,
                        "captured_at": timestamp,
                    },
                )
            )

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport=self.VIEWPORT)
                try:
                    page.goto(f"https://{host}", timeout=self.TIMEOUT_MS, wait_until="networkidle")
                except Exception:
                    # HTTPS failed (no cert, connection refused, etc.) --
                    # fall back to plain HTTP before giving up entirely.
                    # On a fresh page: the failed one is still settling
                    # on Chromium's error page, and that late navigation
                    # would interrupt this one.
                    page.close()
                    page = browser.new_page(viewport=self.VIEWPORT)
                    page.goto(f"http://{host}", timeout=self.TIMEOUT_MS, wait_until="networkidle")

                landing_url = page.url
                # Read the links before navigating away from the page.
                hrefs = page.eval_on_selector_all("a[href]", "links => links.map(a => a.getAttribute('href'))")
                capture(page, "latest", landing_url)

                extra_pages = select_pages(landing_url, hrefs, settings.SCREENSHOT_MAX_PAGES - 1)
                for url in extra_pages:
                    try:
                        page.goto(url, timeout=self.TIMEOUT_MS, wait_until="networkidle")
                    except Exception:
                        # One slow or broken page shouldn't cost the
                        # screenshots already taken; move on.
                        continue
                    # Followed a redirect off the target? Not ours to capture.
                    if urlsplit(page.url).hostname != urlsplit(landing_url).hostname:
                        continue
                    capture(page, f"page:{urlsplit(url).path}", url)
            finally:
                browser.close()

        return findings
