import uuid

from django.db import models

from apps.organizations.models import Organization


class AssetQuerySet(models.QuerySet):
    def with_scoring_findings(self):
        """
        Prefetches each asset's score-relevant findings in ONE extra
        query, onto `scoring_findings`. Asset.risk_score reads that when
        present -- without it, serializing a page of assets runs a
        findings query per asset.
        """
        from apps.findings.models import Finding

        return self.prefetch_related(
            models.Prefetch(
                "findings",
                queryset=Finding.objects.counts_toward_risk().only("id", "asset_id", "severity"),
                to_attr="scoring_findings",
            )
        )


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

    class Source(models.TextChoices):
        DISCOVERED = "discovered", "Discovered"
        MANUAL = "manual", "Added manually"

    # How this asset got here: found by a scanner, or entered by a person
    # (a host discovery can't see, like one with no public DNS history).
    source = models.CharField(max_length=16, choices=Source.choices, default=Source.DISCOVERED)

    class Criticality(models.TextChoices):
        LOW = "low", "Low"
        NORMAL = "normal", "Normal"
        HIGH = "high", "High"
        CROWN_JEWEL = "crown_jewel", "Crown jewel"

    # Business context a scanner can't know: how much it would hurt if
    # this host were compromised. Set by people; used to put issues on
    # the hosts that matter most first.
    criticality = models.CharField(max_length=16, choices=Criticality.choices, default=Criticality.NORMAL)
    # Short free-form labels such as "payments", "production", "agency".
    tags = models.JSONField(blank=True, default=list)

    is_active = models.BooleanField(
        default=True,
        help_text="False once a scan stops confirming this asset still resolves/responds.",
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    objects = AssetQuerySet.as_manager()

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


    @property
    def risk_score(self) -> int:
        # Deferred import avoids circular dependency at module load time
        # (apps.findings imports apps.assets, so top-level import fails)
        from apps.findings.risk_scoring import calculate_risk_score

        findings = getattr(self, "scoring_findings", None)
        if findings is None:
            findings = self.findings.counts_toward_risk()
        return calculate_risk_score(findings)

    @property
    def risk_grade(self) -> str:
        from apps.findings.risk_scoring import grade_for_score
        return grade_for_score(self.risk_score)


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