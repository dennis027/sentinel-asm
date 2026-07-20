"""
Django's own auth machinery fires user_login_failed automatically
whenever authenticate() rejects credentials -- SimpleJWT's login
serializer calls authenticate() internally, so failed login attempts
are already covered by hooking this signal, no changes needed to the
login view itself for the failure case (only the success case needs
manual logging, since a successful JWT issuance never calls Django's
own login() -- see apps/api/auth_views.py).
"""

from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver

from .models import AuthEvent
from .utils import get_client_ip, get_user_agent


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request=None, **kwargs):
    AuthEvent.objects.create(
        event_type=AuthEvent.EventType.LOGIN_FAILED,
        attempted_username=credentials.get("username", "")[:150],
        ip_address=get_client_ip(request) if request else None,
        user_agent=get_user_agent(request) if request else "",
    )