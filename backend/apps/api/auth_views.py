from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import permissions, serializers, status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from apps.audit_logs.models import AuthEvent
from apps.audit_logs.utils import get_client_ip, get_user_agent

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
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            username = request.data.get("username", "")
            user = User.objects.filter(username=username).first()
            AuthEvent.objects.create(
                event_type=AuthEvent.EventType.LOGIN_SUCCESS,
                user=user,
                attempted_username=username[:150],
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
            )
        return response


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
        request=LogoutRequestSerializer,
        responses={204: None, 400: OpenApiResponse(description="Missing or invalid refresh token")},
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