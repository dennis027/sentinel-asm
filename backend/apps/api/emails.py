"""
The account emails: invitations, password-reset links, and notices
when a password or email address changes. Plain text, short, and
sending never raises: a mail outage must not break the request (the
failure is logged, and the person can ask again).
"""

import logging

from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger("apps.accounts")


def _send(to: str, subject: str, body: str) -> bool:
    try:
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [to], fail_silently=False)
        return True
    except Exception as exc:  # noqa: BLE001 - any mail failure is logged, never raised
        logger.error("account_email_failed", extra={"subject": subject, "error": str(exc)})
        return False


def invitation_link(token: str) -> str:
    return f"{settings.FRONTEND_URL}/invite/{token}"


def reset_link(uid: str, token: str) -> str:
    return f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}"


def send_invitation(invitation, token: str) -> bool:
    inviter = invitation.invited_by
    who = (inviter.get_full_name() or inviter.username) if inviter else "Someone"
    return _send(
        invitation.email,
        f"{who} invited you to {invitation.organization.name} on Densight",
        f"{who} invited you to join {invitation.organization.name} on Densight as "
        f"{invitation.get_role_display()}.\n\n"
        f"Accept the invitation:\n{invitation_link(token)}\n\n"
        f"The link works once and expires in {settings.INVITATION_TTL_DAYS} days. "
        "If you weren't expecting this, you can ignore it.\n",
    )


def send_password_reset(user, uid: str, token: str) -> bool:
    minutes = settings.PASSWORD_RESET_TIMEOUT // 60
    return _send(
        user.email,
        "Reset your Densight password",
        f"Someone asked to reset the password for the Densight account {user.username}.\n\n"
        f"Choose a new password:\n{reset_link(uid, token)}\n\n"
        f"The link works once and expires in {minutes} minutes. If it wasn't you, ignore this "
        "email: your password stays as it is.\n",
    )


def send_password_changed(user, how: str) -> bool:
    return _send(
        user.email,
        "Your Densight password was changed",
        f"The password for the Densight account {user.username} was just {how}, and every other "
        "device was signed out.\n\nIf this wasn't you, reset your password now from the sign-in "
        f"page ({settings.FRONTEND_URL}/forgot-password) and tell your organization's admin.\n",
    )


def send_email_changed(user, old_email: str) -> bool:
    return _send(
        old_email,
        "Your Densight email address was changed",
        f"The email address for the Densight account {user.username} was changed from this "
        f"address to {user.email}.\n\nIf this wasn't you, contact your organization's admin "
        "straight away.\n",
    )
