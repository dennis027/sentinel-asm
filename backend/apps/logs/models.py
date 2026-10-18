"""
Server logs: the client's own Linux and Windows machines send their
logs here (through a standard shipper such as Fluent Bit), and
Densight turns the security-relevant ones into detections.

- LogSource: one server sending logs, with its own ingest key.
- LogEvent: one log line or Windows event, normalized into a common
  shape (who, from where, what kind of event) so the same search and
  the same detections work for both operating systems.
- LogDetection: something suspicious found in the events (a brute-force
  attempt, a new administrator, a cleared log). Repeats of the same
  thing update one detection instead of piling up new ones.
"""

import hashlib
import secrets
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class LogSource(models.Model):
    # What sends the logs: a server's operating system, or an application's runtime.
    class OS(models.TextChoices):
        LINUX = "linux", "Linux"
        WINDOWS = "windows", "Windows"
        PYTHON = "python", "Python app"
        NODE = "node", "Node.js app"
        PHP = "php", "PHP app"
        RUBY = "ruby", "Ruby app"
        GO = "go", "Go app"
        JAVA = "java", "Java app"
        DOTNET = "dotnet", ".NET app"
        OTHER = "other", "Other app"

    APPLICATION_TYPES = {OS.PYTHON, OS.NODE, OS.PHP, OS.RUBY, OS.GO, OS.JAVA, OS.DOTNET, OS.OTHER}

    PREFIX = "dsl_"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="log_sources"
    )
    # What people call the server: "web-01", "Domain controller".
    name = models.CharField(max_length=100)
    os = models.CharField(max_length=16, choices=OS.choices)
    # The ingest key is shown once; only its hash is kept.
    key_prefix = models.CharField(max_length=16)
    key_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    # Filled in from what the server sends.
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_host = models.CharField(max_length=255, blank=True, default="")
    events_received = models.BigIntegerField(default=0)
    # Set when the "stopped sending" detection has fired, so it fires once per outage.
    silent_since = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(fields=["organization", "name"], name="unique_log_source_name_per_org")
        ]

    def __str__(self):
        return f"{self.name} ({self.get_os_display()})"

    @staticmethod
    def hash_key(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    def issue_key(self) -> str:
        """Gives the source a new ingest key and returns it; any older key stops working."""
        key = self.PREFIX + secrets.token_urlsafe(32)
        self.key_prefix = key[:12]
        self.key_hash = self.hash_key(key)
        return key

    @property
    def is_application(self) -> bool:
        return self.os in self.APPLICATION_TYPES

    @property
    def status(self) -> str:
        """waiting (never sent anything), receiving, or silent (nothing for a while)."""
        if self.last_seen_at is None:
            return "waiting"
        silent_after = timezone.timedelta(minutes=settings.LOG_SOURCE_SILENT_AFTER_MINUTES)
        return "silent" if timezone.now() - self.last_seen_at > silent_after else "receiving"


class LogEvent(models.Model):
    class Category(models.TextChoices):
        AUTH_SUCCESS = "auth_success", "Sign-in"
        AUTH_FAILURE = "auth_failure", "Failed sign-in"
        PRIVILEGE = "privilege", "Admin rights used"
        ACCOUNT_CHANGE = "account_change", "Account change"
        LOG_TAMPERING = "log_tampering", "Logs cleared"
        SERVICE = "service", "Service or task"
        APP_ERROR = "app_error", "App error"
        HTTP_REQUEST = "http_request", "Web request"
        OTHER = "other", "Other"

    class Level(models.TextChoices):
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"

    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="log_events"
    )
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE, related_name="events")
    occurred_at = models.DateTimeField()
    received_at = models.DateTimeField(auto_now_add=True)
    host = models.CharField(max_length=255, blank=True, default="")
    # sshd, sudo, Security, System...
    program = models.CharField(max_length=128, blank=True, default="")
    # Windows event id (4625...); null for Linux.
    event_id = models.PositiveIntegerField(null=True, blank=True)
    level = models.CharField(max_length=16, choices=Level.choices, default=Level.INFO)
    category = models.CharField(max_length=32, choices=Category.choices, default=Category.OTHER)
    # A short name for what happened, set by the parser: "ssh_failed_password",
    # "windows_logon_failed", "group_member_added"...
    action = models.CharField(max_length=64, blank=True, default="")
    user = models.CharField(max_length=128, blank=True, default="")
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    message = models.TextField(blank=True, default="")
    # What the shipper sent, for the detail view (trimmed if large).
    raw = models.JSONField(blank=True, default=dict)
    # Applications: which service, the HTTP status of a request, and for
    # errors the fingerprint that groups repeats of the same error.
    service = models.CharField(max_length=100, blank=True, default="")
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    fingerprint = models.CharField(max_length=40, blank=True, default="", db_index=True)
    # Kinds of secret masked out before storing ("aws_key", "password"...).
    redacted = models.JSONField(blank=True, default=list)
    # The application version or commit that logged it ("2.15.0", "a1b2c3d").
    release = models.CharField(max_length=100, blank=True, default="")

    class Meta:
        ordering = ["-occurred_at", "-id"]
        indexes = [
            models.Index(fields=["organization", "-occurred_at"]),
            models.Index(fields=["source", "-occurred_at"]),
            models.Index(fields=["organization", "category", "-occurred_at"]),
            models.Index(fields=["organization", "src_ip", "-occurred_at"]),
        ]

    def __str__(self):
        return f"{self.host} {self.program}: {self.message[:60]}"


class LogDetection(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        RESOLVED = "resolved", "Resolved"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="log_detections"
    )
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE, related_name="detections")
    # Which rule fired (see apps.logs.detections.RULES) and on what: an IP, a user...
    rule = models.CharField(max_length=64)
    key = models.CharField(max_length=255, blank=True, default="")
    severity = models.CharField(max_length=16)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    user = models.CharField(max_length=128, blank=True, default="")
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    # How many matching events, from first to last.
    event_count = models.PositiveIntegerField(default=0)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-last_seen"]
        indexes = [models.Index(fields=["organization", "status", "-last_seen"])]

    def __str__(self):
        return f"{self.title} on {self.source.name}"


class ErrorGroup(models.Model):
    """
    Every occurrence of the same application error, as one item -- the
    way error trackers group them: same exception type at the same place
    in the code (or, for errors without a stack trace, the same message
    once numbers and ids are taken out) is the same error.
    """

    class Status(models.TextChoices):
        UNRESOLVED = "unresolved", "Unresolved"
        RESOLVED = "resolved", "Resolved"
        IGNORED = "ignored", "Ignored"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="error_groups"
    )
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE, related_name="error_groups")
    fingerprint = models.CharField(max_length=40)
    exception_type = models.CharField(max_length=200, blank=True, default="")
    # The error's message, from its latest occurrence.
    title = models.CharField(max_length=500)
    # Where in the code: "orders/views.py in checkout".
    culprit = models.CharField(max_length=300, blank=True, default="")
    service = models.CharField(max_length=100, blank=True, default="")
    count = models.PositiveIntegerField(default=0)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    # The latest occurrence's stack trace, for the detail view.
    stacktrace = models.TextField(blank=True, default="")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.UNRESOLVED)
    resolved_at = models.DateTimeField(null=True, blank=True)
    # Times it came back after being marked resolved.
    regressions = models.PositiveIntegerField(default=0)
    # The release it first appeared in, and the latest release it happened in.
    first_release = models.CharField(max_length=100, blank=True, default="")
    last_release = models.CharField(max_length=100, blank=True, default="")

    class Meta:
        ordering = ["-last_seen"]
        constraints = [
            models.UniqueConstraint(fields=["source", "fingerprint"], name="one_error_group_per_fingerprint")
        ]
        indexes = [models.Index(fields=["organization", "status", "-last_seen"])]

    def __str__(self):
        return f"{self.exception_type or 'Error'}: {self.title[:60]}"


class LogAlertRule(models.Model):
    """
    An organization's own detection: "tell me when <text> appears <n>
    times within <m> minutes", optionally narrowed to one source, one
    kind of event or a level. Fires as a detection like the built-in
    rules, and goes to alerts the same way.
    """

    class Level(models.TextChoices):
        ANY = "", "Any level"
        WARNING = "warning", "Warnings and errors"
        ERROR = "error", "Errors only"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="log_alert_rules"
    )
    name = models.CharField(max_length=120)
    # Matched case-insensitively anywhere in the message; empty matches every event.
    contains = models.CharField(max_length=200, blank=True, default="")
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE, null=True, blank=True, related_name="alert_rules")
    category = models.CharField(max_length=32, blank=True, default="", choices=LogEvent.Category.choices)
    level = models.CharField(max_length=16, blank=True, default="", choices=Level.choices)
    threshold = models.PositiveIntegerField(default=1)
    window_minutes = models.PositiveIntegerField(default=5)
    severity = models.CharField(max_length=16, default="medium")
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_fired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @property
    def rule_id(self) -> str:
        return f"custom:{self.id}"

    def matches(self, event) -> bool:
        if self.source_id and event.source_id != self.source_id:
            return False
        if self.category and event.category != self.category:
            return False
        if self.level == self.Level.ERROR and event.level != "error":
            return False
        if self.level == self.Level.WARNING and event.level not in ("warning", "error"):
            return False
        return not self.contains or self.contains.lower() in (event.message or "").lower()

    def events(self, organization_id=None):
        """Every stored event this rule matches."""
        queryset = LogEvent.objects.filter(organization_id=organization_id or self.organization_id)
        if self.source_id:
            queryset = queryset.filter(source_id=self.source_id)
        if self.category:
            queryset = queryset.filter(category=self.category)
        if self.level == self.Level.ERROR:
            queryset = queryset.filter(level="error")
        elif self.level == self.Level.WARNING:
            queryset = queryset.filter(level__in=["warning", "error"])
        if self.contains:
            queryset = queryset.filter(message__icontains=self.contains)
        return queryset
