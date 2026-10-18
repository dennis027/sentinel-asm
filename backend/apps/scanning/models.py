import hashlib
import uuid
from datetime import date

from django.conf import settings
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
    objects = ScanJobManager()
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
    # Set on every job started by one "Run scan" click for a whole
    # domain: one scanner fanned out across all of an organization's
    # assets. Lets the UI report "1,204 of 41,698 done" for that run.
    # Null for single-asset triggers and the daily schedule.
    batch_id = models.UUIDField(null=True, blank=True, db_index=True, editable=False)

    # Where the scan came from, so history can be read as "the nightly
    # run", "Amina's Run scan", "Brian's re-check of shop" rather than
    # thousands of loose rows.
    class Trigger(models.TextChoices):
        SCHEDULE = "schedule", "Daily schedule"
        DOMAIN = "domain", "Run scan"
        RECHECK = "recheck", "Re-check of a host"
        SINGLE = "single", "Single scan"

    trigger = models.CharField(max_length=16, choices=Trigger.choices, default=Trigger.SINGLE, db_index=True)
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+",
        help_text="Who started it; empty for the daily schedule.",
    )
    # Shared by every job started together: one night's schedule for an
    # organization, one Run scan click, one host re-check.
    run_id = models.UUIDField(default=uuid.uuid4, db_index=True, editable=False)

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
    def schedule_run_id(organization_id, run_date: date | None = None) -> uuid.UUID:
        """One run id per organization per day for the daily schedule (the same if beat fires twice)."""
        run_date = run_date or date.today()
        return uuid.uuid5(uuid.NAMESPACE_URL, f"densight:schedule:{organization_id}:{run_date.isoformat()}")

    @staticmethod
    def build_idempotency_key(
        scanner_name: str, target: str, run_date: date | None = None, nonce: str | None = None
    ) -> str:
        """
        Deterministic key = same scanner + same target + same day always
        hashes to the same value. Call this before creating a ScanJob and
        use get_or_create(idempotency_key=...) so a retried task upserts
        instead of duplicating.

        Pass `nonce` (e.g. a random hex string) to deliberately break
        that determinism -- this is what a manual "scan again" trigger
        uses to force a brand-new ScanJob even if one already ran today,
        instead of colliding with the existing key.
        """
        run_date = run_date or date.today()
        raw = f"{scanner_name}:{target}:{run_date.isoformat()}"
        if nonce:
            raw += f":{nonce}"
        return hashlib.sha256(raw.encode()).hexdigest()