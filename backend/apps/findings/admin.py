from django.contrib import admin
from .models import Finding


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "title", "asset", "finding_type", "severity", "is_active", "first_seen", "last_seen",
    )
    list_filter = ("finding_type", "severity", "is_active")
    search_fields = ("title", "asset__value")
    readonly_fields = ("dedupe_key", "first_seen", "last_seen")