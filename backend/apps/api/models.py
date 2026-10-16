import hashlib
import secrets
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class TwoFactorDevice(models.Model):
    """
    A user's authenticator app (Google Authenticator, 1Password, Authy...).
    Created unconfirmed when setup starts; sign-in only asks for a code
    once the user has proved the app works by entering one
    (`confirmed_at`). Losing the phone: an administrator deletes this
    row in the Django admin and the account signs in with a password again.
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="two_factor")
    # Base32 TOTP secret (RFC 6238), shared with the app once via the QR code.
    secret = models.CharField(max_length=64)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    # The last time-step a code was accepted for, so a code can't be replayed.
    last_used_step = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def is_enabled(self) -> bool:
        return self.confirmed_at is not None

    def __str__(self):
        return f"2FA for {self.user} ({'on' if self.is_enabled else 'pending'})"


class ApiKeyQuerySet(models.QuerySet):
    def active(self):
        return self.filter(revoked_at__isnull=True)


class ApiKey(models.Model):
    """
    A read-only key for scripts and integrations (a SIEM pulling
    findings, a CI job checking the grade). It acts as the user who made
    it, can only read (GET), and can be revoked at any time. Only a hash
    is stored: the key itself is shown once, when it is created.
    """

    PREFIX = "sasm_"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(max_length=100)
    # The first characters of the key, so people can tell keys apart.
    prefix = models.CharField(max_length=16, db_index=True)
    key_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    objects = ApiKeyQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.prefix}...) for {self.user}"

    @staticmethod
    def hash(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    @classmethod
    def issue(cls, user, name: str) -> tuple["ApiKey", str]:
        """Creates a key and returns it with the plain-text value, which is never stored."""
        key = cls.PREFIX + secrets.token_urlsafe(32)
        api_key = cls.objects.create(user=user, name=name, prefix=key[:12], key_hash=cls.hash(key))
        return api_key, key

    def revoke(self):
        self.revoked_at = timezone.now()
        self.save(update_fields=["revoked_at"])
