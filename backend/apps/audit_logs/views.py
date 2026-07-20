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