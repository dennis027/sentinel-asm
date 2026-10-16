from django.contrib import admin

from apps.assets.utils import ensure_root_domain_asset

from .models import Membership, Organization


class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 0


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "root_domain", "is_active", "domain_verified_at", "created_at")
    search_fields = ("name", "root_domain")
    list_filter = ("is_active",)
    readonly_fields = ("verification_token",)
    inlines = [MembershipInline]

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        ensure_root_domain_asset(obj)


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role", "created_at")
    list_filter = ("role", "organization")
    search_fields = ("user__username", "organization__name")