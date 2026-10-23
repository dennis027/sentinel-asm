"""
User accounts: your profile, changing your email, signing out every
device, forgotten passwords, and joining an organization through an
invitation (which is also how new accounts are made).

Rules that hold throughout:
- A forgotten-password request answers the same whether or not the
  address has an account, so it can't be used to find out who does.
- Links (invitations, password resets) work once and expire.
- Changing or resetting a password signs out every other device and
  emails the account's owner.
- Every step is recorded in the account's sign-in history.
"""

import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import permissions, serializers, status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken

from apps.audit_logs.activity import record as record_activity
from apps.audit_logs.models import ActivityEvent, AuthEvent
from apps.audit_logs.utils import get_client_ip, get_user_agent
from apps.organizations.models import Invitation, Membership

from . import emails
from .models import TwoFactorDevice

User = get_user_model()
client_logger = logging.getLogger("apps.client")

RESET_SENT = (
    "If an account uses that address, we've sent it a link to choose a new password. "
    "It expires in an hour."
)
BAD_RESET_LINK = "This link is invalid or has expired. Ask for a new one."


def log_auth(request, event_type, user=None, attempted=""):
    AuthEvent.objects.create(
        event_type=event_type,
        user=user,
        attempted_username=(attempted or getattr(user, "username", ""))[:150],
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )


def sign_out_everywhere(user) -> int:
    """Blacklists every refresh token the user holds; returns how many were still active."""
    outstanding = OutstandingToken.objects.filter(user=user).exclude(blacklistedtoken__isnull=False)
    count = outstanding.count()
    BlacklistedToken.objects.bulk_create([BlacklistedToken(token=t) for t in outstanding], ignore_conflicts=True)
    return count


def tokens_for(user) -> dict:
    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}


def email_taken(email: str, exclude_user=None) -> bool:
    users = User.objects.filter(email__iexact=email)
    if exclude_user is not None:
        users = users.exclude(pk=exclude_user.pk)
    return users.exists()


# ---------------------------------------------------------------- profile


class ProfileSerializer(serializers.ModelSerializer):
    two_factor_enabled = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "date_joined", "last_login",
                  "two_factor_enabled"]
        read_only_fields = ["id", "username", "email", "date_joined", "last_login", "two_factor_enabled"]

    def get_two_factor_enabled(self, user) -> bool:
        return TwoFactorDevice.objects.filter(user=user, confirmed_at__isnull=False).exists()

    def validate_first_name(self, value):
        return value.strip()

    def validate_last_name(self, value):
        return value.strip()


class MeView(APIView):
    """
    GET   /api/auth/me/   -- who is signed in
    PATCH /api/auth/me/   {"first_name": ..., "last_name": ...}
    The username can't be changed; the email address has its own endpoint
    because it needs the current password.
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: ProfileSerializer})
    def get(self, request):
        return Response(ProfileSerializer(request.user).data)

    @extend_schema(request=ProfileSerializer, responses={200: ProfileSerializer})
    def patch(self, request):
        serializer = ProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        log_auth(request, AuthEvent.EventType.PROFILE_UPDATED, request.user)
        return Response(serializer.data)


class ChangeEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    current_password = serializers.CharField(write_only=True)


class ChangeEmailView(APIView):
    """
    POST /api/auth/me/email/  {"email": "new@example.com", "current_password": "..."}
    Needs the current password, so an unattended signed-in browser can't
    redirect the account's password resets to someone else. The old
    address is told about the change.
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=ChangeEmailSerializer, responses={200: ProfileSerializer})
    def post(self, request):
        serializer = ChangeEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data["current_password"]):
            return Response({"current_password": ["Incorrect password."]}, status=status.HTTP_400_BAD_REQUEST)
        new_email = serializer.validated_data["email"].strip().lower()
        if new_email == (user.email or "").lower():
            return Response({"email": ["That is already your email address."]}, status=status.HTTP_400_BAD_REQUEST)
        if email_taken(new_email, exclude_user=user):
            return Response({"email": ["Another account already uses that address."]},
                            status=status.HTTP_400_BAD_REQUEST)
        old_email = user.email
        user.email = new_email
        user.save(update_fields=["email"])
        log_auth(request, AuthEvent.EventType.EMAIL_CHANGED, user)
        if old_email:
            emails.send_email_changed(user, old_email)
        return Response(ProfileSerializer(user).data)


class SignOutEverywhereView(APIView):
    """
    POST /api/auth/sessions/revoke/
    Ends every session on every device, including this one: no refresh
    token the account holds can be used again. Access tokens already
    handed out expire on their own within minutes.
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=None, responses={200: OpenApiResponse(description="{'signed_out': n}")})
    def post(self, request):
        count = sign_out_everywhere(request.user)
        log_auth(request, AuthEvent.EventType.SIGNED_OUT_EVERYWHERE, request.user)
        return Response({"signed_out": count, "detail": "Signed out on every device."})


# ---------------------------------------------------------------- forgotten password


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetRequestView(APIView):
    """
    POST /api/auth/password-reset/  {"email": "..."}
    Always answers the same, whether or not the address has an account.
    Rate-limited per address of the caller.
    """

    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_reset"

    @extend_schema(request=PasswordResetRequestSerializer, responses={200: OpenApiResponse(description=RESET_SENT)})
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"].strip()
        for user in User.objects.filter(email__iexact=email, is_active=True):
            if not user.has_usable_password():
                continue
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            emails.send_password_reset(user, uid, default_token_generator.make_token(user))
            log_auth(request, AuthEvent.EventType.PASSWORD_RESET_REQUESTED, user)
        return Response({"detail": RESET_SENT})


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)


class PasswordResetConfirmView(APIView):
    """
    POST /api/auth/password-reset/confirm/  {"uid": ..., "token": ..., "new_password": ...}
    Sets the new password, signs out every device and emails a notice.
    The link stops working once used (the token covers the password).
    Two-factor sign-in, if on, still applies at the next sign-in.
    """

    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_reset"

    @extend_schema(request=PasswordResetConfirmSerializer, responses={200: OpenApiResponse(description="Done")})
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            user = User.objects.get(pk=force_str(urlsafe_base64_decode(data["uid"])), is_active=True)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            user = None
        if user is None or not default_token_generator.check_token(user, data["token"]):
            return Response({"token": [BAD_RESET_LINK]}, status=status.HTTP_400_BAD_REQUEST)
        try:
            validate_password(data["new_password"], user=user)
        except DjangoValidationError as exc:
            return Response({"new_password": list(exc.messages)}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(data["new_password"])
        user.save(update_fields=["password"])
        sign_out_everywhere(user)
        log_auth(request, AuthEvent.EventType.PASSWORD_RESET, user)
        emails.send_password_changed(user, "reset with an emailed link")
        return Response({"detail": "Password changed. Sign in with your new password.", "username": user.username})


# ---------------------------------------------------------------- invitations


def find_invitation(token: str, lock=False):
    queryset = Invitation.objects.select_related("organization", "invited_by")
    if lock:
        # Only the invitation row: the inviter is an optional (outer) join.
        queryset = queryset.select_for_update(of=("self",))
    return queryset.filter(token_hash=Invitation.hash_token(token)).first()


GONE = {
    "accepted": "This invitation has already been used.",
    "revoked": "This invitation was cancelled. Ask the person who sent it for a new one.",
    "expired": "This invitation has expired. Ask the person who sent it for a new one.",
}


class InvitationDetailView(APIView):
    """
    GET /api/invitations/{token}/
    What the link is for (organization, role, who sent it) and whether the
    invited address already has an account (sign in) or not (create one).
    """

    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "invitation"

    @extend_schema(responses={200: OpenApiResponse(description="The invitation")})
    def get(self, request, token):
        invitation = find_invitation(token)
        if invitation is None:
            return Response({"detail": "This invitation link isn't valid."}, status=status.HTTP_404_NOT_FOUND)
        inviter = invitation.invited_by
        return Response({
            "organization": invitation.organization.name,
            "email": invitation.email,
            "role": invitation.role,
            "role_label": invitation.get_role_display(),
            "invited_by": (inviter.get_full_name() or inviter.username) if inviter else None,
            "expires_at": invitation.expires_at,
            "status": invitation.status,
            "detail": GONE.get(invitation.status, ""),
            "account_exists": User.objects.filter(email__iexact=invitation.email, is_active=True).exists(),
        })


class AcceptInvitationSerializer(serializers.Serializer):
    # Only when creating a new account (not signed in):
    password = serializers.CharField(write_only=True, required=False)
    first_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=150)


class AcceptInvitationView(APIView):
    """
    POST /api/invitations/{token}/accept/
    Signed in as the invited address: joins the organization.
    Not signed in, and the address has no account: creates one (username
    and email are the invited address; the link proves the person
    received it), joins, and returns sign-in tokens.
    Not signed in, and the address already has an account: 409 -- sign
    in first, so nobody joins on someone else's behalf.
    """

    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "invitation"

    @extend_schema(request=AcceptInvitationSerializer, responses={200: OpenApiResponse(description="Joined")})
    def post(self, request, token):
        serializer = AcceptInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            invitation = find_invitation(token, lock=True)
            if invitation is None:
                return Response({"detail": "This invitation link isn't valid."}, status=status.HTTP_404_NOT_FOUND)
            if invitation.status != "pending":
                return Response({"detail": GONE[invitation.status], "status": invitation.status},
                                status=status.HTTP_410_GONE)

            created = False
            if request.user.is_authenticated:
                user = request.user
                if (user.email or "").lower() != invitation.email.lower():
                    return Response(
                        {"detail": f"This invitation is for {invitation.email}. Sign in with that account, "
                                   "or sign out to create it.", "code": "wrong_account"},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            else:
                if User.objects.filter(email__iexact=invitation.email, is_active=True).exists() or \
                        User.objects.filter(username__iexact=invitation.email).exists():
                    return Response(
                        {"detail": f"{invitation.email} already has an account. Sign in to accept.",
                         "code": "sign_in_required"},
                        status=status.HTTP_409_CONFLICT,
                    )
                password = serializer.validated_data.get("password", "")
                if not password:
                    return Response({"password": ["Choose a password."]}, status=status.HTTP_400_BAD_REQUEST)
                user = User(
                    username=invitation.email.lower(), email=invitation.email.lower(),
                    first_name=serializer.validated_data.get("first_name", "").strip(),
                    last_name=serializer.validated_data.get("last_name", "").strip(),
                )
                try:
                    validate_password(password, user=user)
                except DjangoValidationError as exc:
                    return Response({"password": list(exc.messages)}, status=status.HTTP_400_BAD_REQUEST)
                user.set_password(password)
                user.save()
                created = True

            membership, joined = Membership.objects.get_or_create(
                user=user, organization=invitation.organization, defaults={"role": invitation.role}
            )
            invitation.accepted_at = timezone.now()
            invitation.accepted_by = user
            invitation.save(update_fields=["accepted_at", "accepted_by"])
            # Any other pending invitations to this organization for the same address are spent too.
            Invitation.objects.filter(
                organization=invitation.organization, email__iexact=invitation.email,
                accepted_at__isnull=True, revoked_at__isnull=True,
            ).exclude(pk=invitation.pk).update(revoked_at=timezone.now())

        if created:
            log_auth(request, AuthEvent.EventType.ACCOUNT_CREATED, user)
        if joined:
            record_activity(
                user, invitation.organization, ActivityEvent.Verb.INVITATION_ACCEPTED,
                f"{user.username} joined as {membership.get_role_display()}",
            )
        body = {"organization": str(invitation.organization.id), "role": membership.role,
                "username": user.username, "created_account": created}
        if created:
            body.update(tokens_for(user))
        return Response(body, status=status.HTTP_200_OK)


# ---------------------------------------------------------------- browser errors


class ClientErrorSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=2000)
    stack = serializers.CharField(max_length=10000, required=False, allow_blank=True)
    url = serializers.CharField(max_length=1000, required=False, allow_blank=True)
    type = serializers.CharField(max_length=200, required=False, allow_blank=True)


class ClientErrorView(APIView):
    """
    POST /api/client-errors/  {"message", "stack", "url", "type"}
    The web app reports its own unexpected errors here. They are logged
    like any backend error, so with Densight's self-logging on they show
    up under Logs -> Errors, grouped, with the browser's stack trace.
    """

    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "client_errors"

    @extend_schema(request=ClientErrorSerializer, responses={204: None})
    def post(self, request):
        serializer = ClientErrorSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        client_logger.error(
            f"Browser error: {data['message'][:300]}",
            extra={
                "error": {"type": data.get("type") or "Error", "message": data["message"], "stack": data.get("stack", "")},
                "page_url": data.get("url", ""),
                "user": request.user.username if request.user.is_authenticated else "",
                "user_agent": get_user_agent(request),
                "service": "densight-web",
            },
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
