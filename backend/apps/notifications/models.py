import uuid

from django.db import models

from apps.findings.models import Finding
from apps.organizations.models import Organization


class NotificationRule(models.Model):
    """
    "Email <recipient_email> whenever a NEW finding at or above
    <min_severity> shows up for <organization>."

    Deliberately a plain recipient_email field rather than a link to a
    User/Membership model -- this project doesn't have org membership
    built yet, and a rule shouldn't require one. If/when membership
    exists, this can gain a `user` FK alongside the email field without
    breaking anything currently using it.

    Multiple rules per org are supported on purpose (e.g. security-team@
    wants everything, while an exec only wants critical/high).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="notification_rules"
    )
    class Channel(models.TextChoices):
        EMAIL = "email", "Email"
        # An HTTPS endpoint that accepts {"text": "..."} -- the format
        # Slack, Mattermost, Discord (/slack) and Teams workflows all
        # take, and the simplest way into a ticketing tool.
        WEBHOOK = "webhook", "Webhook"

    channel = models.CharField(max_length=16, choices=Channel.choices, default=Channel.EMAIL)
    # Exactly one of these is set, depending on `channel`.
    recipient_email = models.EmailField(blank=True, default="")
    webhook_url = models.URLField(max_length=500, blank=True, default="")
    min_severity = models.CharField(
        max_length=16,
        choices=Finding.Severity.choices,
        default=Finding.Severity.MEDIUM,
        help_text="Notify for findings at this severity or higher.",
    )
    is_active = models.BooleanField(default=True)
    # Email rules only: also send the weekly PDF report to this address
    # (see apps.notifications.tasks.send_weekly_reports).
    weekly_report = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["organization", "channel", "recipient_email", "webhook_url"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "recipient_email", "webhook_url"],
                name="unique_rule_per_org_destination",
            )
        ]

    @property
    def destination(self) -> str:
        return self.webhook_url if self.channel == self.Channel.WEBHOOK else self.recipient_email

    def __str__(self):
        return f"{self.destination} @ {self.organization.name} (>= {self.min_severity})"