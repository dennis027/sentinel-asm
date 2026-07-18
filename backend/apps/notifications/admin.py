from django.contrib import admin
from .models import NotificationRule


@admin.register(NotificationRule)
class NotificationRuleAdmin(admin.ModelAdmin):
    list_display = ("recipient_email", "organization", "min_severity", "is_active", "created_at")
    list_filter = ("min_severity", "is_active", "organization")
    search_fields = ("recipient_email", "organization__name")