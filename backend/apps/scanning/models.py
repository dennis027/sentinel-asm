import hashlib
import uuid
from datetime import date

from django.db import models

from apps.assets.models import Asset
from apps.organizations.models import Organization


class ScanJobManager(models.Manager):
    def create(self, **kwargs):
        if "idempotency_key" not in kwargs:
            scanner_name = kwargs.get("scanner_name")
            asset = kwargs.get("asset")
            organization = kwargs.get("organization")
            if scanner_name and (asset or organization):
                if isinstance(asset, Asset):
                    target = asset.value
                elif asset is not None:
                    target = str(asset)
                else:
                    target = organization.root_domain
                kwargs["idempotency_key"] = ScanJob.build_idempotency_key(
                    scanner_name, target
                )

        if "idempotency_key" not in kwargs:
            return super().create(**kwargs)

        return self.get_or_create(idempotency_key=kwargs["idempotency_key"], defaults=kwargs)[0]


class ScanJob(models.Model):
    # objects = ScanJobManager()
    """
    One execution of one scanner plugin. Two kinds of target:

    - Org-level scans (e.g. subdomain discovery) run against
      `organization` alone -- `asset` is null because the scan is what
      *produces* new Assets.
    - Asset-level scans (nmap, nuclei, httpx, SSL check) run against a
      specific `asset`.

    `idempotency_key` is what makes retries safe: Celery's `apply_async`
    can be retried by the broker on worker crash, and beat can in rare
    cases double-fire -- upserting on this key instead of blind insert
    means neither creates a duplicate ScanJob row.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        RETRYING = "retrying", "Retrying"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="scan_jobs"
    )
    asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="scan_jobs",
        null=True,
        blank=True,
        help_text="Null for org-level scans (e.g. subdomain discovery).",
    )
    # Matches the `name` attribute on a BaseScanner plugin subclass,
    # e.g. "subfinder", "nmap", "nuclei", "httpx", "ssl_expiry".
    scanner_name = models.CharField(max_length=64)

    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    celery_task_id = models.CharField(max_length=255, blank=True, default="")

    idempotency_key = models.CharField(max_length=64, unique=True, editable=False)

    error_message = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["organization", "scanner_name", "status"]),
        ]

    def __str__(self):
        target = self.asset.value if self.asset else self.organization.root_domain
        return f"{self.scanner_name} -> {target} [{self.status}]"

    @staticmethod
    def build_idempotency_key(scanner_name: str, target: str, run_date: date | None = None) -> str:
        """
        Deterministic key = same scanner + same target + same day always
        hashes to the same value. Call this before creating a ScanJob and
        use get_or_create(idempotency_key=...) so a retried task upserts
        instead of duplicating.
        """
        run_date = run_date or date.today()
        raw = f"{scanner_name}:{target}:{run_date.isoformat()}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.idempotency_key:
            target = self.asset.value if self.asset else self.organization.root_domain
            self.idempotency_key = self.build_idempotency_key(self.scanner_name, target)
        super().save(*args, **kwargs)