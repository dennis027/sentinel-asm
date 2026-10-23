from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from apps.api import account_views
from apps.api.auth_views import (
    ApiKeyDetailView,
    ApiKeyListView,
    ChangePasswordView,
    LoginView,
    LogoutView,
    SignInHistoryView,
    TwoFactorConfirmView,
    TwoFactorDisableView,
    TwoFactorSetupView,
    TwoFactorStatusView,
)

from apps.logs.ingest import ingest
from apps.logs.views import client_file

from .metrics import metrics_view

urlpatterns = [
    path("admin/", admin.site.urls),
    path("health/", include("health.urls")),
    # Servers' log shippers post here with their own key (apps.logs.ingest).
    path("api/ingest/", ingest, name="log-ingest"),
    path("api/logs/clients/<str:name>", client_file, name="log-client-file"),
    path("api/", include("apps.api.urls")),
    path("api/token/", LoginView.as_view(), name="token-obtain-pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("api/token/verify/", TokenVerifyView.as_view(), name="token-verify"),
    path("api/auth/login/", LoginView.as_view(), name="auth-login"),
    path("api/auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("api/auth/change-password/", ChangePasswordView.as_view(), name="auth-change-password"),
    path("api/auth/2fa/", TwoFactorStatusView.as_view(), name="auth-2fa"),
    path("api/auth/2fa/setup/", TwoFactorSetupView.as_view(), name="auth-2fa-setup"),
    path("api/auth/2fa/confirm/", TwoFactorConfirmView.as_view(), name="auth-2fa-confirm"),
    path("api/auth/2fa/disable/", TwoFactorDisableView.as_view(), name="auth-2fa-disable"),
    path("api/auth/api-keys/", ApiKeyListView.as_view(), name="auth-api-keys"),
    path("api/auth/api-keys/<uuid:key_id>/", ApiKeyDetailView.as_view(), name="auth-api-key"),
    path("api/auth/sign-ins/", SignInHistoryView.as_view(), name="auth-sign-ins"),
    path("api/auth/me/", account_views.MeView.as_view(), name="auth-me"),
    path("api/auth/me/email/", account_views.ChangeEmailView.as_view(), name="auth-change-email"),
    path("api/auth/sessions/revoke/", account_views.SignOutEverywhereView.as_view(), name="auth-sign-out-everywhere"),
    path("api/auth/password-reset/", account_views.PasswordResetRequestView.as_view(), name="auth-password-reset"),
    path("api/auth/password-reset/confirm/", account_views.PasswordResetConfirmView.as_view(),
         name="auth-password-reset-confirm"),
    path("api/invitations/<str:token>/", account_views.InvitationDetailView.as_view(), name="invitation-detail"),
    path("api/invitations/<str:token>/accept/", account_views.AcceptInvitationView.as_view(), name="invitation-accept"),
    path("api/client-errors/", account_views.ClientErrorView.as_view(), name="client-errors"),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("metrics", metrics_view, name="prometheus-django-metrics"),
]
