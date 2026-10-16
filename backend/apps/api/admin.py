from django.contrib import admin

from .models import ApiKey, TwoFactorDevice


@admin.register(TwoFactorDevice)
class TwoFactorDeviceAdmin(admin.ModelAdmin):
    """Deleting a row here turns two-factor sign-in off for that user (a lost phone)."""

    list_display = ["user", "confirmed_at", "created_at"]
    search_fields = ["user__username", "user__email"]
    readonly_fields = ["user", "confirmed_at", "created_at", "last_used_step"]
    exclude = ["secret"]


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ["name", "user", "prefix", "created_at", "last_used_at", "revoked_at"]
    search_fields = ["name", "user__username", "prefix"]
    readonly_fields = ["user", "prefix", "key_hash", "created_at", "last_used_at"]
