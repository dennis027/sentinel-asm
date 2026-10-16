import uuid

from django.conf import settings
from django.db import models


class AuthEvent(models.Model):
    """
    Immutable record of an authentication-related event, for security
    audit purposes. Never updated after creation -- if something needs
    correcting, create a new row, don't edit history.
    """

    class EventType(models.TextChoices):
        LOGIN_SUCCESS = "login_success", "Login success"
        LOGIN_FAILED = "login_failed", "Login failed"
        LOGOUT = "logout", "Logout"
        PASSWORD_CHANGED = "password_changed", "Password changed"
        TWO_FACTOR_ENABLED = "two_factor_enabled", "Two-factor sign-in turned on"
        TWO_FACTOR_DISABLED = "two_factor_disabled", "Two-factor sign-in turned off"
        API_KEY_CREATED = "api_key_created", "API key created"
        API_KEY_REVOKED = "api_key_revoked", "API key revoked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Nullable: a failed login with a nonexistent/wrong username has no
    # real user to attach to -- record the attempted username as text
    # instead of forcing a (possibly misleading) FK.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="auth_events",
    )
    attempted_username = models.CharField(max_length=150, blank=True, default="")
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "event_type"]),
            models.Index(fields=["event_type", "created_at"]),
        ]

    def __str__(self):
        who = self.user.username if self.user else (self.attempted_username or "unknown")
        return f"{self.event_type} - {who} @ {self.created_at.isoformat()}"


class ActivityEvent(models.Model):
    """
    "Who did what" inside an organization: scans started, findings
    triaged or assigned, members added, rules changed. Like AuthEvent
    it is append-only. The actor's name is copied in so the trail
    still reads correctly after an account is deleted.
    """

    class Verb(models.TextChoices):
        ORG_CREATED = "org_created", "Created the organization"
        ORG_UPDATED = "org_updated", "Changed organization settings"
        DOMAIN_VERIFIED = "domain_verified", "Verified the domain"
        MEMBER_ADDED = "member_added", "Added a member"
        MEMBER_ROLE_CHANGED = "member_role_changed", "Changed a member's role"
        MEMBER_REMOVED = "member_removed", "Removed a member"
        SCAN_STARTED = "scan_started", "Started a scan"
        FINDING_TRIAGED = "finding_triaged", "Triaged a finding"
        FINDING_ASSIGNED = "finding_assigned", "Assigned a finding"
        ASSET_ADDED = "asset_added", "Added an asset"
        RULE_CREATED = "rule_created", "Added a notification rule"
        RULE_DELETED = "rule_deleted", "Deleted a notification rule"
        REPORT_DOWNLOADED = "report_downloaded", "Downloaded a report"
        FINDING_COMMENTED = "finding_commented", "Commented on a finding"
        FINDING_REOPENED = "finding_reopened", "A fixed finding came back"
        ACCEPTANCE_EXPIRED = "acceptance_expired", "A risk acceptance expired"
        ASSET_UPDATED = "asset_updated", "Changed an asset's details"
        SCOPE_CHANGED = "scope_changed", "Changed what may be scanned"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="activity"
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    actor_name = models.CharField(max_length=150, blank=True, default="")
    # The finding this is about, when it is about one -- builds that
    # finding's history.
    finding = models.ForeignKey(
        "findings.Finding", on_delete=models.SET_NULL, null=True, blank=True, related_name="activity"
    )
    verb = models.CharField(max_length=32, choices=Verb.choices)
    # One readable line, written when it happened: "Triaged 'Open port 3389' as risk accepted".
    summary = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["organization", "created_at"])]

    def __str__(self):
        return f"{self.actor_name}: {self.summary}"
