from django.contrib import admin
from .models import AuthEvent


@admin.register(AuthEvent)
class AuthEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "user", "attempted_username", "ip_address", "created_at")
    list_filter = ("event_type",)
    search_fields = ("user__username", "attempted_username", "ip_address")
    readonly_fields = [f.name for f in AuthEvent._meta.fields]  # immutable log -- no editing via admin

    def has_add_permission(self, request):
        return False  # audit entries are created by the app, never manually