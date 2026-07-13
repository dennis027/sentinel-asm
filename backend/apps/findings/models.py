import hashlib
import uuid

from django.db import models

from apps.assets.models import Asset
from apps.scanning.models import ScanJob


class Finding(models.Model):
    """
    A single result produced by a ScanJob: an open port, a missing
    security header, an expiring cert, a nuclei match, etc.

    Historical tracking / "yesterday vs today" diffing works WITHOUT a
    separate history table: findings are never deleted.

    - Each scan run upserts on (asset, dedupe_key):
        * match found      -> bump last_seen, ensure is_active=True
        * no longer found  -> flip is_active=False (resolved)
        * genuinely new    -> create with first_seen=now
    - "New findings today"      = Finding.objects.filter(first_seen__date=today)
    - "Resolved findings today" = Finding.objects.filter(is_active=False, last_seen__date=yesterday)
    - "Still open"               = Finding.objects.filter(is_active=True)
    """

    class FindingType(models.TextChoices):
        OPEN_PORT = "open_port", "Open port"
        MISSING_HEADER = "missing_header", "Missing security header"
        EXPIRED_SSL = "expired_ssl", "Expired/expiring SSL certificate"
        EXPOSED_SERVICE = "exposed_service", "Exposed service"
        NUCLEI_MATCH = "nuclei_match", "Nuclei match"
        SUBDOMAIN_DISCOVERED = "subdomain_discovered", "New subdomain discovered"
        DNS_CHANGE = "dns_change", "DNS record change"

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_job = models.ForeignKey(
        ScanJob,
        on_delete=models.SET_NULL,
        null=True,
        related_name="findings",
        help_text="The scan run that most recently confirmed this finding.",
    )
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="findings")

    finding_type = models.CharField(max_length=32, choices=FindingType.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    # Raw scanner output for this specific finding (e.g. the nuclei template
    # match, the full header dump) -- kept for drill-down/debugging.
    raw_data = models.JSONField(blank=True, default=dict)

    # Identifies "the same finding" across scan runs so re-scans upsert
    # instead of duplicating, e.g. sha256("open_port:443") or
    # sha256("nuclei_match:CVE-2024-XXXX").
    dedupe_key = models.CharField(max_length=64, editable=False)

    is_active = models.BooleanField(default=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen"]
        constraints = [
            models.UniqueConstraint(
                fields=["asset", "dedupe_key"], name="unique_finding_per_asset"
            )
        ]
        indexes = [
            models.Index(fields=["asset", "is_active"]),
            models.Index(fields=["finding_type", "severity"]),
        ]

    def __str__(self):
        return f"{self.title} ({self.asset.value})"

    @staticmethod
    def build_dedupe_key(finding_type: str, identifier: str) -> str:
        """
        `identifier` should be whatever makes this finding unique within
        an asset, e.g. a port number ("443"), a header name
        ("missing:Strict-Transport-Security"), or a CVE/template id.
        """
        raw = f"{finding_type}:{identifier}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.dedupe_key:
            raise ValueError(
                "dedupe_key must be set explicitly via Finding.build_dedupe_key() "
                "before saving -- it defines what 'the same finding' means."
            )
        super().save(*args, **kwargs)