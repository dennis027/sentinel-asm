"""
Website screenshot capture via Playwright (headless Chromium).

Stores the PNG under MEDIA_ROOT/screenshots/<asset_id>/<timestamp>.png
and records the relative path + built URL in the Finding's raw_data.
Local disk storage for now -- swap for S3-class object storage before
this needs to run across multiple worker replicas that don't share a
filesystem (see architecture notes / README).

Single evolving finding per asset (constant identifier, like
ssl_expiry's cert-status finding) -- this represents "current visual
state," re-captured and overwritten each scan, not a history of every
screenshot ever taken. Old screenshot files on disk are intentionally
left in place (not deleted) even though only the latest is referenced,
which is a reasonable trade-off until a cleanup/retention job exists.
"""

from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .registry import register_scanner


@register_scanner
class ScreenshotScanner(BaseScanner):
    name = "screenshot"
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
        relative_path = f"screenshots/{target.id}/{timestamp}.png"
        absolute_path = Path(settings.MEDIA_ROOT) / relative_path
        absolute_path.parent.mkdir(parents=True, exist_ok=True)

        page_title = ""
        final_url = ""

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport=self.VIEWPORT)
                try:
                    page.goto(f"https://{host}", timeout=self.TIMEOUT_MS, wait_until="networkidle")
                except Exception:
                    # HTTPS failed (no cert, connection refused, etc.) --
                    # fall back to plain HTTP before giving up entirely.
                    page.goto(f"http://{host}", timeout=self.TIMEOUT_MS, wait_until="networkidle")

                page_title = page.title()
                final_url = page.url
                page.screenshot(path=str(absolute_path), full_page=False)
            finally:
                browser.close()

        screenshot_url = f"{settings.MEDIA_URL}{relative_path}"

        return [
            RawFinding(
                finding_type=Finding.FindingType.SCREENSHOT,
                identifier="latest",
                severity=Finding.Severity.INFO,
                title=f"Screenshot captured: {page_title or host}",
                description=f"Visual snapshot of {final_url or host}.",
                raw_data={
                    "screenshot_path": relative_path,
                    "screenshot_url": screenshot_url,
                    "page_title": page_title,
                    "final_url": final_url,
                    "captured_at": timestamp,
                },
            )
        ]