import uuid

from django.db import models


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