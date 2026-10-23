"""
The check before a scan: what it will cover and what will stop it
before anyone presses Run. Answers, in one response:

- which hosts are in scope, and how many the never-scan list removes
- whether the host names still exist in DNS (a sample, checked in
  parallel), and which point inside a private network and are refused
- whether each scanner can run on the worker (nmap, nuclei, ... installed)
- whether one is already running, and roughly how long the scan takes

so a scan of 43 hosts that no longer exist reads "43 will be skipped"
up front instead of "43 failed" an hour later.
"""

import os
import statistics
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import timedelta

from django.core.cache import cache
from django.db.models import F
from django.utils import timezone

from .models import ScanJob
from .plugins.registry import get_scanner, list_scanners
from .targets import classify_host
from .tasks import WORKER_STATUS_KEY

# Host names resolved per check. Enough to see a pattern; the response
# says how many were checked when there are more.
SAMPLE = 200
DNS_WORKERS = 32
DNS_DEADLINE_SECONDS = 8
CACHE_SECONDS = 5 * 60
# Scans that run at once on the worker(s), for the time estimate only.
SCAN_WORKERS = int(os.environ.get("ASM_SCAN_WORKERS", "4"))
# Used when a scanner has never run here.
DEFAULT_SECONDS = 20
SHOWN = 10

UNFINISHED = [ScanJob.Status.PENDING, ScanJob.Status.RUNNING, ScanJob.Status.RETRYING]


def check_hosts(hosts: list[str]) -> dict[str, str]:
    """{host: classify_host(host)}, in parallel, giving up on slow answers after a few seconds."""
    if not hosts:
        return {}
    pool = ThreadPoolExecutor(max_workers=min(DNS_WORKERS, len(hosts)))
    futures = {pool.submit(classify_host, host): host for host in hosts}
    done, _ = wait(futures, timeout=DNS_DEADLINE_SECONDS)
    pool.shutdown(wait=False, cancel_futures=True)
    return {host: (future.result() if future in done else "unknown") for future, host in futures.items()}


def _host_check(organization, in_scope) -> dict:
    key = f"preflight:hosts:{organization.id}"
    cached = cache.get(key)
    if cached is not None:
        return cached
    # Most important hosts first, so the sample covers the ones that matter.
    order = {"crown_jewel": 0, "high": 1, "normal": 2, "low": 3}
    sample = sorted(in_scope.values_list("value", "criticality")[: SAMPLE * 5], key=lambda row: order.get(row[1], 2))
    results = check_hosts([value for value, _ in sample[:SAMPLE]])
    by_state: dict[str, list[str]] = {"ok": [], "missing": [], "private": [], "unknown": []}
    for host, state in results.items():
        by_state[state].append(host)
    summary = {
        "checked": len(results),
        "resolves": len(by_state["ok"]),
        "missing": len(by_state["missing"]),
        "private": len(by_state["private"]),
        "unknown": len(by_state["unknown"]),
        "missing_hosts": sorted(by_state["missing"])[:SHOWN],
        "private_hosts": sorted(by_state["private"])[:SHOWN],
        "checked_at": timezone.now().isoformat(),
    }
    cache.set(key, summary, CACHE_SECONDS)
    return summary


def _typical_seconds(organization, scanner_name: str) -> float:
    durations = [
        (finished - started).total_seconds()
        for started, finished in ScanJob.objects.filter(
            organization=organization, scanner_name=scanner_name, status=ScanJob.Status.SUCCESS,
            started_at__isnull=False, finished_at__gte=F("started_at"),
        ).order_by("-finished_at").values_list("started_at", "finished_at")[:50]
    ]
    return round(statistics.median(durations), 1) if durations else DEFAULT_SECONDS


def build_preflight(organization, scanner_names: list[str] | None = None) -> dict:
    names = scanner_names or list_scanners()
    active = organization.assets.filter(is_active=True)
    in_scope = organization.scannable_assets()
    in_scope_count = in_scope.count()
    hosts = _host_check(organization, in_scope)
    running = set(
        ScanJob.objects.filter(
            organization=organization, status__in=UNFINISHED, batch_id__isnull=False,
            created_at__gte=timezone.now() - timedelta(days=1),
        ).values_list("scanner_name", flat=True).distinct()
    )

    worker = cache.get(WORKER_STATUS_KEY)
    worker_tools = (worker or {}).get("missing_tools", {})

    # Of the hosts checked, the share that would be skipped by scanners that connect.
    missing_share = hosts["missing"] / hosts["checked"] if hosts["checked"] else 0

    scanners, jobs, work_seconds = [], 0, 0.0
    for name in names:
        scanner = get_scanner(name)()
        org_level = scanner.applies_to == "organization"
        targets = 1 if org_level else in_scope_count
        skipped = 0 if org_level or not scanner.needs_address else round(in_scope_count * missing_share)
        missing_tools = worker_tools.get(name, [])
        typical = _typical_seconds(organization, name)
        if not missing_tools and name not in running:
            jobs += targets
            work_seconds += (targets - skipped) * typical
        scanners.append({
            "name": name,
            "label": scanner.label or name,
            "applies_to": scanner.applies_to,
            "targets": targets,
            "likely_skipped": skipped,
            "missing_tools": missing_tools,
            "running": name in running,
            "typical_seconds": typical,
        })

    warnings = []
    if worker is None:
        warnings.append(
            "No scan worker has checked in for the last 30 minutes. Scans will wait in the queue until one is running."
        )
    if not organization.scans_allowed:
        warnings.append("Scanning is off until the domain is verified and the organization is active.")
    if hosts["missing"]:
        warnings.append(
            f"{hosts['missing']} of the {hosts['checked']} host names checked no longer exist in DNS. "
            "Scanners that connect to hosts will skip them."
        )
    if hosts["private"]:
        warnings.append(
            f"{hosts['private']} host name(s) point inside a private network and are never scanned."
        )
    for scanner in scanners:
        if scanner["missing_tools"]:
            warnings.append(
                f"{scanner['label']} can't run: {', '.join(scanner['missing_tools'])} isn't installed on the worker."
            )
        elif scanner["running"]:
            warnings.append(f"{scanner['label']} is already running; it won't be started again.")

    return {
        "scans_allowed": organization.scans_allowed,
        "hosts": {
            "active": active.count(),
            "in_scope": in_scope_count,
            "excluded": active.count() - in_scope_count,
            **hosts,
        },
        "scanners": scanners,
        "jobs": jobs,
        "estimated_seconds": round(work_seconds / max(1, SCAN_WORKERS)),
        "worker_seen_at": (worker or {}).get("seen_at"),
        "warnings": warnings,
        "ready": organization.scans_allowed and any(not s["missing_tools"] and not s["running"] for s in scanners),
    }
