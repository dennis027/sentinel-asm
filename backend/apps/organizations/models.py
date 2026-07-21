import uuid

from django.db import models
from django.conf import settings

class Organization(models.Model):
    """
    Tenant boundary. Every Asset, ScanJob, and Finding belongs to
    exactly one Organization -- this is what makes "multiple companies"
    support possible later without a schema change.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    # The domain you're allowed to scan for this org, e.g. "example.com".
    # Subdomain discovery scanners use this as their starting point.
    root_domain = models.CharField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name
    

class Membership(models.Model):
    """
    Links a User to an Organization with a role, per the role table in
    the architecture doc. This is what "org-scoped permissions" is
    actually built on -- without this model there's no way to know
    which organizations a given user should be allowed to see at all.
    """

    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        ADMIN = "admin", "Admin"
        ANALYST = "analyst", "Security Analyst"
        VIEWER = "viewer", "Viewer"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships"
    )
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="memberships"
    )
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.VIEWER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "organization"], name="unique_membership")
        ]
        ordering = ["organization", "role"]

    def __str__(self):
        return f"{self.user.username} - {self.organization.name} ({self.role})"