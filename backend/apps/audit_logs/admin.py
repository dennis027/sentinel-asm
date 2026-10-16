from django.contrib import admin
from .models import ActivityEvent, AuthEvent


@admin.register(ActivityEvent)
class ActivityEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "organization", "actor_name", "verb", "summary")
    list_filter = ("verb",)
    search_fields = ("summary", "actor_name", "organization__name")
    readonly_fields = [f.name for f in ActivityEvent._meta.fields]

    def has_add_permission(self, request):
        return False


@admin.register(AuthEvent)
class AuthEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "user", "attempted_username", "ip_address", "created_at")
    list_filter = ("event_type",)
    search_fields = ("user__username", "attempted_username", "ip_address")
    readonly_fields = [f.name for f in AuthEvent._meta.fields]  # immutable log -- no editing via admin

    def has_add_permission(self, request):
        return False  # audit entries are created by the app, never manually