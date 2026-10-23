import hashlib
import re
import uuid

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models

from apps.assets.models import Asset
from apps.scanning.models import ScanJob


class FindingQuerySet(models.QuerySet):
    def counts_toward_risk(self):
        """
        Findings that should lower a risk score: still detected, not
        triaged away, and an actual issue rather than inventory. Every
        place that scores risk goes through this so they can't disagree.
        """
        return self.filter(is_active=True, status=Finding.Status.OPEN).exclude(
            finding_type__in=Finding.INVENTORY_TYPES
        )

    def by_severity(self):
        """Worst first, then most recently seen. (`severity` is stored
        as text, so ordering on the column itself would be alphabetical.)"""
        rank = models.Case(
            *[
                models.When(severity=severity, then=models.Value(position))
                for position, severity in enumerate(Finding.Severity.values)
            ],
            output_field=models.IntegerField(),
        )
        return self.annotate(severity_rank=rank).order_by("-severity_rank", "-last_seen")


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
        SCREENSHOT = "screenshot", "Website screenshot"
        EMAIL_SECURITY = "email_security", "Email spoofing protection"
        SUBDOMAIN_TAKEOVER = "subdomain_takeover", "Subdomain takeover risk"
        WEAK_TLS = "weak_tls", "Weak TLS configuration"
        OUTDATED_SOFTWARE = "outdated_software", "Outdated software"
        SECURITY_TXT = "security_txt", "Security contact (security.txt)"
        EXPOSED_FILE = "exposed_file", "Exposed sensitive file"
        ZONE_TRANSFER = "zone_transfer", "DNS zone transfer allowed"
        CORS = "cors_misconfiguration", "CORS misconfiguration"
        INSECURE_COOKIE = "insecure_cookie", "Insecure cookie"
        NO_HTTPS = "https_not_enforced", "HTTPS not enforced"
        LOOKALIKE_DOMAIN = "lookalike_domain", "Lookalike domain"
        EXPOSED_PANEL = "exposed_panel", "Exposed admin panel"
        API_EXPOSURE = "api_exposure", "Exposed API documentation"
        DNS_HYGIENE = "dns_hygiene", "DNS hygiene"
        CERT_ISSUED = "cert_issued", "Certificate issued"
        UNUSUAL_CERT = "unusual_certificate", "Unusual certificate"
        EXPOSED_SECRET = "exposed_secret", "Secret in public code"
        PUBLIC_BUCKET = "public_bucket", "Public cloud storage"
        DOMAIN_REGISTRATION = "domain_registration", "Domain registration"
        POLICY_VIOLATION = "policy_violation", "Breaks a policy"

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        """
        An analyst's verdict, separate from is_active. is_active is what
        the scanner last saw (still there / gone); status is what a
        human decided about it. Only OPEN findings count toward risk
        scores, and re-scans never reset a verdict.
        """

        OPEN = "open", "Open"
        ACCEPTED = "accepted", "Risk accepted"
        FALSE_POSITIVE = "false_positive", "False positive"

    # Types that record WHAT EXISTS (a subdomain, a DNS record, what the
    # page looks like) rather than something wrong with it. They're
    # kept as findings so changes show up as new/resolved, but they
    # aren't issues: they don't affect risk scores and the UI lists
    # them separately.
    INVENTORY_TYPES = (
        FindingType.SUBDOMAIN_DISCOVERED,
        FindingType.DNS_CHANGE,
        FindingType.SCREENSHOT,
        FindingType.CERT_ISSUED,
    )

    objects = FindingQuerySet.as_manager()

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
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    status_note = models.TextField(blank=True, default="")
    status_changed_at = models.DateTimeField(null=True, blank=True)
    status_changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="triaged_findings",
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    # When a scan first stopped detecting this finding. Cleared if it
    # comes back. This is what "fixed this week" is counted from.
    resolved_at = models.DateTimeField(null=True, blank=True)
    # Who is responsible for fixing it. The fix-by date is not stored:
    # it is first_seen plus the severity's SLA (apps.findings.remediation),
    # so changing the SLA policy re-dates every open finding at once.
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="assigned_findings",
    )
    # A risk acceptance can be time-limited: on this date the finding
    # goes back to open (apps.findings.tasks.expire_risk_acceptances),
    # so "we'll live with it for now" can't quietly become forever.
    accepted_until = models.DateField(null=True, blank=True)
    # How many times a scan found this again after it had been fixed,
    # and when that last happened. A fix that doesn't stick is worth
    # knowing about: the cause wasn't dealt with.
    reopened_count = models.PositiveIntegerField(default=0)
    reopened_at = models.DateTimeField(null=True, blank=True)
    # CVE ids the finding is about (from the scanner's data and title),
    # matched against CISA's catalogue of vulnerabilities known to be
    # exploited in the wild (KnownExploitedVulnerability).
    cves = ArrayField(models.CharField(max_length=32), blank=True, default=list)

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

    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    @classmethod
    def extract_cves(cls, *texts) -> list[str]:
        found = set()
        for text in texts:
            found.update(match.upper() for match in cls.CVE_PATTERN.findall(str(text or "")))
        return sorted(found)

    def save(self, *args, **kwargs):
        if not self.cves:
            self.cves = self.extract_cves(self.title, self.raw_data)
        if not self.dedupe_key:
            raise ValueError(
                "dedupe_key must be set explicitly via Finding.build_dedupe_key() "
                "before saving -- it defines what 'the same finding' means."
            )
        super().save(*args, **kwargs)


class RiskSnapshot(models.Model):
    """
    One organization's headline numbers on one day. Recorded whenever
    the risk summary is computed (and daily by celery-beat), so the
    dashboard can show whether things are getting better or worse --
    the current state alone can't answer that.
    """

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="risk_snapshots"
    )
    date = models.DateField()
    score = models.FloatField(null=True, blank=True)
    grade = models.CharField(max_length=2, blank=True, default="")
    asset_count = models.PositiveIntegerField(default=0)
    assets_at_risk = models.PositiveIntegerField(default=0)
    open_issues = models.PositiveIntegerField(default=0)
    critical_high = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["date"]
        constraints = [
            models.UniqueConstraint(fields=["organization", "date"], name="one_snapshot_per_org_per_day")
        ]

    def __str__(self):
        return f"{self.organization} {self.date}: {self.grade}"


class FindingComment(models.Model):
    """
    A note in the discussion under a finding: "fixed in tonight's
    deploy", "this host belongs to the marketing agency". Like the
    activity log, the author's name is copied in so it still reads
    correctly after an account is deleted.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    author_name = models.CharField(max_length=150)
    body = models.TextField(max_length=4000)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.author_name} on {self.finding_id}: {self.body[:40]}"


class KnownExploitedVulnerability(models.Model):
    """
    One entry of CISA's Known Exploited Vulnerabilities catalogue: a CVE
    that attackers are confirmed to be using. Synced daily
    (apps.findings.kev.sync); a finding about one of these goes to the
    top of the queue whatever its severity score says.
    """

    cve_id = models.CharField(max_length=32, primary_key=True)
    vendor = models.CharField(max_length=255, blank=True, default="")
    product = models.CharField(max_length=255, blank=True, default="")
    name = models.CharField(max_length=500, blank=True, default="")
    description = models.TextField(blank=True, default="")
    required_action = models.TextField(blank=True, default="")
    date_added = models.DateField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    # "Known" when ransomware groups are known to use it.
    ransomware = models.BooleanField(default=False)

    class Meta:
        ordering = ["-date_added"]

    def __str__(self):
        return f"{self.cve_id} {self.name}"


class SurfacePolicy(models.Model):
    """
    A rule a team sets for what its attack surface may look like ("no RDP
    on the internet", "nothing on Heroku", "no host names with 'dev'").
    Every host that breaks it gets a "Breaks a policy" finding, which is
    resolved once the host complies or the policy is turned off.
    """

    class Kind(models.TextChoices):
        PORT = "port", "Port must not be open"
        TECHNOLOGY = "technology", "Software must not be used"
        HOSTNAME = "hostname", "Host names must not match"
        PROVIDER = "provider", "Must not be hosted on"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="surface_policies"
    )
    name = models.CharField(max_length=120)
    kind = models.CharField(max_length=16, choices=Kind.choices)
    # A port number, a software name, a host name pattern (* wildcards)
    # or a hosting provider, depending on `kind`.
    value = models.CharField(max_length=120)
    severity = models.CharField(max_length=16, choices=Finding.Severity.choices, default=Finding.Severity.MEDIUM)
    # What to do about it, shown on each finding.
    guidance = models.TextField(blank=True, default="")
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.organization})"

    @property
    def rule(self) -> str:
        """The rule as a sentence, e.g. "port 3389 must not be open"."""
        return {
            self.Kind.PORT: f"port {self.value} must not be open",
            self.Kind.TECHNOLOGY: f"{self.value} must not be used",
            self.Kind.HOSTNAME: f"no host name may match {self.value}",
            self.Kind.PROVIDER: f"nothing may be hosted on {self.value}",
        }[self.kind]
