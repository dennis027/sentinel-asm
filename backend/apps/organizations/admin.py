from django.contrib import admin
from .models import Membership, Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "root_domain", "is_active", "created_at")
    search_fields = ("name", "root_domain")
    list_filter = ("is_active",)


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role", "created_at")
    list_filter = ("role", "organization")
    search_fields = ("user__username", "organization__name")