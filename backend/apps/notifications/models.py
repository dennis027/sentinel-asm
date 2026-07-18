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
    recipient_email = models.EmailField()
    min_severity = models.CharField(
        max_length=16,
        choices=Finding.Severity.choices,
        default=Finding.Severity.MEDIUM,
        help_text="Notify for findings at this severity or higher.",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["organization", "recipient_email"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "recipient_email"],
                name="unique_rule_per_org_recipient",
            )
        ]

    def __str__(self):
        return f"{self.recipient_email} @ {self.organization.name} (>= {self.min_severity})"