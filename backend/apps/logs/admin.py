from django.contrib import admin

from .models import ErrorGroup, LogDetection, LogSource


@admin.register(LogSource)
class LogSourceAdmin(admin.ModelAdmin):
    list_display = ["name", "organization", "os", "last_seen_at", "events_received"]
    search_fields = ["name", "last_host"]
    readonly_fields = ["key_prefix", "key_hash", "events_received", "last_seen_at", "last_host"]


@admin.register(LogDetection)
class LogDetectionAdmin(admin.ModelAdmin):
    list_display = ["title", "source", "severity", "status", "event_count", "last_seen"]
    list_filter = ["severity", "status", "rule"]


@admin.register(ErrorGroup)
class ErrorGroupAdmin(admin.ModelAdmin):
    list_display = ["exception_type", "title", "source", "count", "status", "last_seen"]
    list_filter = ["status"]
