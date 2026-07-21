"""
Custom Prometheus metrics for the scanning pipeline -- the business
metrics that actually matter for this platform, on top of the generic
HTTP request metrics django-prometheus already provides for free.

These answer the operational questions a security-tool team actually
asks: is the scan pipeline keeping up, which scanners fail most, how
long do scans take, is the finding rate normal or spiking.
"""

from prometheus_client import Counter, Histogram

SCAN_JOBS_TOTAL = Counter(
    "asm_scan_jobs_total",
    "Total scan jobs processed, by scanner and final status.",
    ["scanner_name", "status"],
)

SCAN_JOB_DURATION_SECONDS = Histogram(
    "asm_scan_job_duration_seconds",
    "Scan job execution time in seconds, by scanner.",
    ["scanner_name"],
)

FINDINGS_CREATED_TOTAL = Counter(
    "asm_findings_created_total",
    "New (not re-confirmed) findings created, by type and severity.",
    ["finding_type", "severity"],
)

NOTIFICATIONS_SENT_TOTAL = Counter(
    "asm_notifications_sent_total",
    "Notification emails successfully dispatched.",
)