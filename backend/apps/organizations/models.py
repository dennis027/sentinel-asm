import secrets
import uuid

from django.conf import settings
from django.db import models


def generate_verification_token() -> str:
    return secrets.token_hex(16)


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
    # Proof the org actually controls root_domain: the owner publishes
    # `verification_record_value` as a TXT record at
    # `verification_record_name`, and the verify endpoint checks DNS for
    # it. Scans are refused until this is set whenever
    # settings.REQUIRE_DOMAIN_VERIFICATION is on -- otherwise anyone
    # with an account could point nmap/nuclei at a domain they don't own.
    verification_token = models.CharField(
        max_length=64, default=generate_verification_token, editable=False
    )
    domain_verified_at = models.DateTimeField(null=True, blank=True)
    # Days to fix an issue, by severity, where this organization differs
    # from settings.REMEDIATION_SLA_DAYS. See `sla_policy`.
    sla_days = models.JSONField(blank=True, default=dict)
    # Host names under root_domain that must never be scanned -- usually
    # ones run by someone else (a hosted shop, a marketing agency's
    # site) that the organization isn't allowed to test. "*.name"
    # covers everything under name. See `is_out_of_scope`.
    scope_exclusions = models.JSONField(blank=True, default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @property
    def is_domain_verified(self) -> bool:
        return self.domain_verified_at is not None

    @property
    def verification_record_name(self) -> str:
        return f"_sentinel-asm.{self.root_domain}"

    @property
    def verification_record_value(self) -> str:
        return f"sentinel-asm-verification={self.verification_token}"

    @property
    def sla_policy(self) -> dict[str, int]:
        """Days to fix, by severity: the server default with this organization's changes."""
        return {**settings.REMEDIATION_SLA_DAYS, **(self.sla_days or {})}

    def is_out_of_scope(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for pattern in self.scope_exclusions or []:
            if pattern.startswith("*."):
                if host.endswith(pattern[1:]):
                    return True
            elif host == pattern:
                return True
        return False

    def out_of_scope_q(self, field: str = "value"):
        """A filter matching this organization's assets that must not be scanned."""
        from django.db.models import Q

        condition = Q(pk__in=[])
        for pattern in self.scope_exclusions or []:
            if pattern.startswith("*."):
                condition |= Q(**{f"{field}__endswith": pattern[1:]})
            else:
                condition |= Q(**{field: pattern})
        return condition

    def scannable_assets(self):
        """Active assets that are in scope -- what a scan of "everything" covers."""
        return self.assets.filter(is_active=True).exclude(self.out_of_scope_q())

    @property
    def scans_allowed(self) -> bool:
        if not self.is_active:
            return False
        return self.is_domain_verified or not settings.REQUIRE_DOMAIN_VERIFICATION
    

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

    # Each role includes everything the roles below it can do:
    #   viewer  -- read-only
    #   analyst -- + trigger scans, triage findings
    #   admin   -- + manage notification rules and org settings, verify the domain
    #   owner   -- + delete the organization
    ROLE_RANK = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2, Role.OWNER: 3}

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