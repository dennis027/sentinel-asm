import django_filters
from django.db.models import Q

from .compliance import CONTROLS, finding_types_for
from .models import Finding
from apps.organizations.models import Organization

from .remediation import overdue_q_for


class FindingFilter(django_filters.FilterSet):
    # Findings hang off assets, not organizations directly -- this is
    # what lets the UI show one organization's findings at a time.
    organization = django_filters.UUIDFilter(field_name="asset__organization")
    # triaged=true  -> anything an analyst has ruled on (accepted / false positive)
    # triaged=false -> still open
    triaged = django_filters.BooleanFilter(method="filter_triaged")
    # kind=issue     -> things that are wrong (ports, headers, certs, vulnerabilities)
    # kind=inventory -> records of what exists (subdomains, DNS, screenshots)
    kind = django_filters.ChoiceFilter(
        choices=[("issue", "Issue"), ("inventory", "Inventory")], method="filter_kind"
    )

    # assignee=me | none | <user id>
    assignee = django_filters.CharFilter(method="filter_assignee")
    overdue = django_filters.BooleanFilter(method="filter_overdue")
    # control=owasp:A05 -> findings of the kinds mapped to that control
    control = django_filters.ChoiceFilter(choices=[(c, c) for c in CONTROLS], method="filter_control")

    # regressed=true -> fixed once, then found again
    regressed = django_filters.BooleanFilter(method="filter_regressed")
    # asset_criticality=crown_jewel -> issues on the hosts that matter most
    asset_criticality = django_filters.CharFilter(field_name="asset__criticality")

    class Meta:
        model = Finding
        fields = ["organization", "asset", "finding_type", "severity", "is_active", "status"]

    def filter_assignee(self, queryset, name, value):
        if value == "none":
            return queryset.filter(assignee__isnull=True)
        if value == "me":
            return queryset.filter(assignee=self.request.user)
        if value.isdigit():
            return queryset.filter(assignee_id=int(value))
        return queryset.none()

    def filter_overdue(self, queryset, name, value):
        # Each organization's own SLA decides what is overdue in it.
        organizations = Organization.objects.filter(
            id__in=queryset.order_by().values("asset__organization").distinct()
        )
        condition = overdue_q_for(organizations) & ~Q(finding_type__in=Finding.INVENTORY_TYPES)
        return queryset.filter(condition) if value else queryset.exclude(condition)

    def filter_regressed(self, queryset, name, value):
        return queryset.filter(reopened_count__gt=0) if value else queryset.filter(reopened_count=0)

    def filter_control(self, queryset, name, value):
        return queryset.filter(finding_type__in=finding_types_for(value))

    def filter_kind(self, queryset, name, value):
        if value == "inventory":
            return queryset.filter(finding_type__in=Finding.INVENTORY_TYPES)
        return queryset.exclude(finding_type__in=Finding.INVENTORY_TYPES)

    def filter_triaged(self, queryset, name, value):
        if value:
            return queryset.exclude(status=Finding.Status.OPEN)
        return queryset.filter(status=Finding.Status.OPEN)
