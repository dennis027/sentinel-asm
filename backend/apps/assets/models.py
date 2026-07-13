import uuid

from django.db import models

from apps.organizations.models import Organization


class Asset(models.Model):
    """
    A single discovered host: a subdomain, a bare domain, or an IP.
    This is the spine of the whole platform -- ScanJobs run against
    Assets, Findings belong to Assets.
    """

    class AssetType(models.TextChoices):
        DOMAIN = "domain", "Domain"
        SUBDOMAIN = "subdomain", "Subdomain"
        IP = "ip", "IP address"
        URL = "url", "URL"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="assets"
    )
    asset_type = models.CharField(max_length=16, choices=AssetType.choices)
    # The actual hostname/IP/URL, e.g. "api.company.com" or "203.0.113.5".
    value = models.CharField(max_length=512)

    is_active = models.BooleanField(
        default=True,
        help_text="False once a scan stops confirming this asset still resolves/responds.",
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["value"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "value"], name="unique_asset_per_org"
            )
        ]
        indexes = [
            models.Index(fields=["organization", "asset_type"]),
        ]

    def __str__(self):
        return self.value


class Technology(models.Model):
    """
    A detected technology on an Asset (e.g. nginx 1.25, WordPress 6.4),
    typically produced by an httpx/Wappalyzer-style fingerprinting scan.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(
        Asset, on_delete=models.CASCADE, related_name="technologies"
    )
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=64, blank=True, default="")
    # e.g. "web-server", "cms", "language", "framework", "analytics"
    category = models.CharField(max_length=64, blank=True, default="")

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["asset", "name", "version"], name="unique_technology_per_asset"
            )
        ]

    def __str__(self):
        return f"{self.name} {self.version}".strip()