from django.contrib import admin
from .models import Asset, Technology


class TechnologyInline(admin.TabularInline):
    model = Technology
    extra = 0
    readonly_fields = ("first_seen", "last_seen")


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("value", "organization", "asset_type", "is_active", "last_seen")
    list_filter = ("asset_type", "is_active", "organization")
    search_fields = ("value",)
    inlines = [TechnologyInline]


@admin.register(Technology)
class TechnologyAdmin(admin.ModelAdmin):
    list_display = ("name", "version", "category", "asset", "last_seen")
    list_filter = ("category",)
    search_fields = ("name", "asset__value")