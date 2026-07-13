from django.contrib import admin
from .models import ScanJob


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = (
        "scanner_name", "organization", "asset", "status", "created_at", "finished_at",
    )
    list_filter = ("scanner_name", "status", "organization")
    readonly_fields = ("idempotency_key", "created_at")