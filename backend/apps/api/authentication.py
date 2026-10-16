"""
API key authentication for scripts and integrations:

    Authorization: Api-Key sasm_...

A key acts as the user who created it, but only for reading: any
request that would change something is refused, so a leaked key can
expose data but never alter it, start scans or lock anyone out.
"""

from django.utils import timezone
from rest_framework import authentication, exceptions, permissions

from .models import ApiKey

KEYWORD = "Api-Key"


class ApiKeyAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode("latin-1")
        if not header.startswith(f"{KEYWORD} "):
            return None
        key = header[len(KEYWORD) + 1:].strip()
        api_key = (
            ApiKey.objects.active().select_related("user").filter(key_hash=ApiKey.hash(key)).first()
        )
        if api_key is None or not api_key.user.is_active:
            raise exceptions.AuthenticationFailed("Invalid or revoked API key.")
        if request.method not in permissions.SAFE_METHODS:
            raise exceptions.PermissionDenied("API keys are read-only. Sign in to make changes.")
        ApiKey.objects.filter(id=api_key.id).update(last_used_at=timezone.now())
        return api_key.user, api_key

    def authenticate_header(self, request):
        return KEYWORD
