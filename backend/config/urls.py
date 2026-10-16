from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

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

from .metrics import metrics_view

urlpatterns = [
    path("admin/", admin.site.urls),
    path("health/", include("health.urls")),
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
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("metrics", metrics_view, name="prometheus-django-metrics"),
]
