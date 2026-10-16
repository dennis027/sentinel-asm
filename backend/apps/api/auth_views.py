from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Q
from django.http import Http404
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, OpenApiTypes, extend_schema
from rest_framework import permissions, serializers, status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from apps.audit_logs.models import AuthEvent
from apps.audit_logs.utils import get_client_ip, get_user_agent

from . import totp
from .models import ApiKey, TwoFactorDevice

User = get_user_model()

# Plain APIViews (LogoutView, ChangePasswordView below) can't be
# auto-introspected by drf-spectacular the way GenericAPIView/ViewSets
# with a serializer_class can -- without these request/response
# serializers and the @extend_schema decorators below, both endpoints
# would still WORK but show up in Swagger with an undocumented,
# guessable-only request body.
class LogoutRequestSerializer(serializers.Serializer):
    refresh = serializers.CharField(help_text="The refresh token to blacklist.")


class ChangePasswordRequestSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)


class ChangePasswordResponseSerializer(serializers.Serializer):
    detail = serializers.CharField()




class LoginView(TokenObtainPairView):
    """
    POST /api/auth/login/
    Same behavior as the base TokenObtainPairView (issues access +
    refresh tokens), plus: rate-limiting against brute-force attempts
    (see DEFAULT_THROTTLE_RATES['login'] in settings), and audit
    logging of the successful attempt. Failed attempts are logged
    separately via the user_login_failed signal -- see
    apps/audit_logs/signals.py -- since Django/SimpleJWT fire that
    automatically and don't need duplicating here.
    """

    throttle_classes = [ScopedRateThrottle]
    # ScopedRateThrottle reads ITS scope from view.throttle_scope, not
    # from any attribute set on the throttle class itself -- that's
    # what the rate in DEFAULT_THROTTLE_RATES["login"] actually keys on.
    throttle_scope = "login"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as exc:
            raise InvalidToken(exc.args[0])
        user = serializer.user

        # With two-factor sign-in on, a correct password alone is not
        # enough: the response asks for the code, and the client sends
        # username, password and `otp` together.
        device = TwoFactorDevice.objects.filter(user=user, confirmed_at__isnull=False).first()
        if device is not None:
            code = str(request.data.get("otp", "")).strip()
            if not code:
                return Response(
                    {"otp_required": True, "detail": "Enter the 6-digit code from your authenticator app."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            step = totp.matching_step(device.secret, code)
            # A code can be used once: a step at or before the last one
            # accepted is a replay.
            if step is None or step <= device.last_used_step:
                self._log(request, AuthEvent.EventType.LOGIN_FAILED, user)
                return Response(
                    {"otp_required": True, "otp": ["That code isn't right. Codes change every 30 seconds."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            device.last_used_step = step
            device.save(update_fields=["last_used_step"])

        self._log(request, AuthEvent.EventType.LOGIN_SUCCESS, user)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

    @staticmethod
    def _log(request, event_type, user):
        AuthEvent.objects.create(
            event_type=event_type,
            user=user,
            attempted_username=user.username[:150],
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
        )


class LogoutView(APIView):
    """
    POST /api/auth/logout/
    Body: {"refresh": "<refresh_token>"}

    Immediately blacklists the refresh token server-side -- it can
    never be used again to mint a new access token, even if it hasn't
    expired yet. The currently-held access token remains technically
    valid until its own short expiry (see SIMPLE_JWT ACCESS_TOKEN_LIFETIME)
    since JWTs are stateless by design; this is the standard, accepted
    trade-off for JWT-based logout (the alternative -- checking a
    blacklist on every single request -- reintroduces the server-side
    session lookup JWTs exist to avoid). The frontend is responsible
    for discarding both tokens from memory immediately regardless.
    """

    permission_classes = [permissions.IsAuthenticated]
    @extend_schema(
        request=LogoutRequestSerializer,
        responses={204: None, 400: OpenApiResponse(description="Missing or invalid refresh token")},
    )
    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"refresh": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response({"refresh": ["Invalid or already-blacklisted token."]}, status=status.HTTP_400_BAD_REQUEST)

        AuthEvent.objects.create(
            event_type=AuthEvent.EventType.LOGOUT,
            user=request.user,
            attempted_username=request.user.username,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class ChangePasswordView(APIView):
    """
    POST /api/auth/change-password/
    Body: {"current_password": "...", "new_password": "..."}

    Requires the user's CURRENT password, not just an active session --
    prevents someone who's grabbed an unattended, still-logged-in
    browser tab from silently locking the real owner out.

    On success, blacklists every outstanding refresh token for this
    user (not just the one on the current request) -- if the account
    was compromised, changing the password should end every other
    session too, not just the one that made this request.
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        request=ChangePasswordRequestSerializer,
        responses={
            200: ChangePasswordResponseSerializer,
            400: OpenApiResponse(description="Wrong current password or new password too weak"),
        },
    )
    def post(self, request):
        current_password = request.data.get("current_password", "")
        new_password = request.data.get("new_password", "")

        if not current_password or not new_password:
            return Response(
                {"detail": "Both current_password and new_password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not request.user.check_password(current_password):
            return Response({"current_password": ["Incorrect password."]}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(new_password, user=request.user)
        except DjangoValidationError as exc:
            return Response({"new_password": list(exc.messages)}, status=status.HTTP_400_BAD_REQUEST)

        request.user.set_password(new_password)
        request.user.save(update_fields=["password"])

        # Revoke every other active session -- see docstring above.
        outstanding = OutstandingToken.objects.filter(user=request.user)
        BlacklistedToken.objects.bulk_create(
            [BlacklistedToken(token=t) for t in outstanding],
            ignore_conflicts=True,
        )

        AuthEvent.objects.create(
            event_type=AuthEvent.EventType.PASSWORD_CHANGED,
            user=request.user,
            attempted_username=request.user.username,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
        )
        return Response({"detail": "Password changed. All other sessions have been logged out."})


def _log_event(request, event_type):
    AuthEvent.objects.create(
        event_type=event_type,
        user=request.user,
        attempted_username=request.user.username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )


class TwoFactorCodeSerializer(serializers.Serializer):
    code = serializers.CharField()


class TwoFactorDisableSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)


class TwoFactorStatusView(APIView):
    """GET /api/auth/2fa/ -- whether two-factor sign-in is on for the current user."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        device = TwoFactorDevice.objects.filter(user=request.user, confirmed_at__isnull=False).first()
        return Response({"enabled": device is not None, "enabled_at": device.confirmed_at if device else None})


class TwoFactorSetupView(APIView):
    """
    POST /api/auth/2fa/setup/
    Starts turning on two-factor sign-in: makes a new secret and returns
    it as a QR code for the authenticator app. Nothing changes at sign-in
    until a code from the app is confirmed (POST /api/auth/2fa/confirm/).
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=None, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        if TwoFactorDevice.objects.filter(user=request.user, confirmed_at__isnull=False).exists():
            return Response(
                {"detail": "Two-factor sign-in is already on. Turn it off first to move it to another app."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        secret = totp.new_secret()
        TwoFactorDevice.objects.update_or_create(
            user=request.user, defaults={"secret": secret, "confirmed_at": None, "last_used_step": 0}
        )
        uri = totp.provisioning_uri(secret, request.user.username)
        return Response({"secret": secret, "otpauth_uri": uri, "qr_svg": totp.qr_svg(uri)})


class TwoFactorConfirmView(APIView):
    """POST /api/auth/2fa/confirm/ {"code": "123456"} -- proves the app works and turns two-factor on."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=TwoFactorCodeSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        device = TwoFactorDevice.objects.filter(user=request.user, confirmed_at__isnull=True).first()
        if device is None:
            return Response({"detail": "Start the setup first."}, status=status.HTTP_400_BAD_REQUEST)
        step = totp.matching_step(device.secret, str(request.data.get("code", "")))
        if step is None:
            return Response(
                {"code": ["That code isn't right. Check the time on your phone and try the newest code."]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        device.confirmed_at = timezone.now()
        device.last_used_step = step
        device.save(update_fields=["confirmed_at", "last_used_step"])
        _log_event(request, AuthEvent.EventType.TWO_FACTOR_ENABLED)
        return Response({"enabled": True, "enabled_at": device.confirmed_at})


class TwoFactorDisableView(APIView):
    """POST /api/auth/2fa/disable/ {"password": "..."} -- turns two-factor sign-in off."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=TwoFactorDisableSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        if not request.user.check_password(str(request.data.get("password", ""))):
            return Response({"password": ["Incorrect password."]}, status=status.HTTP_400_BAD_REQUEST)
        deleted, _ = TwoFactorDevice.objects.filter(user=request.user).delete()
        if deleted:
            _log_event(request, AuthEvent.EventType.TWO_FACTOR_DISABLED)
        return Response({"enabled": False, "enabled_at": None})


class ApiKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = ApiKey
        fields = ["id", "name", "prefix", "created_at", "last_used_at"]
        read_only_fields = ["id", "prefix", "created_at", "last_used_at"]


class ApiKeyListView(APIView):
    """
    GET  /api/auth/api-keys/          -- your active keys (never the keys themselves)
    POST /api/auth/api-keys/ {"name"} -- a new read-only key, shown once in `key`
    """

    permission_classes = [permissions.IsAuthenticated]
    MAX_KEYS = 20

    @extend_schema(responses={200: ApiKeySerializer(many=True)})
    def get(self, request):
        return Response(ApiKeySerializer(ApiKey.objects.active().filter(user=request.user), many=True).data)

    @extend_schema(request=ApiKeySerializer, responses={201: OpenApiTypes.OBJECT})
    def post(self, request):
        serializer = ApiKeySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if ApiKey.objects.active().filter(user=request.user).count() >= self.MAX_KEYS:
            return Response(
                {"detail": f"You already have {self.MAX_KEYS} keys. Revoke one you no longer use."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        api_key, key = ApiKey.issue(request.user, serializer.validated_data["name"].strip())
        _log_event(request, AuthEvent.EventType.API_KEY_CREATED)
        return Response({**ApiKeySerializer(api_key).data, "key": key}, status=status.HTTP_201_CREATED)


class ApiKeyDetailView(APIView):
    """DELETE /api/auth/api-keys/{id}/ -- revokes the key; anything using it stops working at once."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={204: None})
    def delete(self, request, key_id):
        api_key = ApiKey.objects.active().filter(user=request.user, id=key_id).first()
        if api_key is None:
            raise Http404
        api_key.revoke()
        _log_event(request, AuthEvent.EventType.API_KEY_REVOKED)
        return Response(status=status.HTTP_204_NO_CONTENT)


class SignInHistoryView(APIView):
    """
    GET /api/auth/sign-ins/
    The current user's recent sign-ins, failed attempts on their
    username and other account security events, newest first -- so
    people can spot a sign-in that wasn't them.
    """

    permission_classes = [permissions.IsAuthenticated]
    SHOWN = 25

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        events = AuthEvent.objects.filter(
            Q(user=request.user) | Q(user__isnull=True, attempted_username=request.user.username)
        )[: self.SHOWN]
        return Response([
            {
                "id": event.id,
                "event_type": event.event_type,
                "label": event.get_event_type_display(),
                "ip_address": event.ip_address,
                "user_agent": event.user_agent,
                "created_at": event.created_at,
            }
            for event in events
        ])
