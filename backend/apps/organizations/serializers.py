from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework import serializers

from apps.scanning.targets import validate_root_domain

from .models import Membership, Organization


class OrganizationSerializer(serializers.ModelSerializer):
    # The requesting user's own role in this org -- lets the frontend
    # hide actions the API would reject anyway. Null for superusers who
    # aren't members.
    my_role = serializers.SerializerMethodField()
    domain_verified = serializers.BooleanField(source="is_domain_verified", read_only=True)
    verification_required = serializers.SerializerMethodField()
    verification_record_name = serializers.CharField(read_only=True)
    verification_record_value = serializers.CharField(read_only=True)
    scans_allowed = serializers.BooleanField(read_only=True)
    # Days to fix, by severity. Read: the policy in force (the server
    # default with this organization's changes). Write: the days to use.
    sla_days = serializers.DictField(child=serializers.IntegerField(min_value=1, max_value=365), required=False)
    # Hosts never to scan: "shop.example.com", or "*.agency.example.com"
    # for everything under a name.
    scope_exclusions = serializers.ListField(
        child=serializers.CharField(max_length=255), required=False, max_length=200
    )

    SLA_ORDER = ["critical", "high", "medium", "low"]

    class Meta:
        model = Organization
        fields = [
            "id", "name", "root_domain", "is_active", "created_at", "updated_at",
            "my_role", "domain_verified", "domain_verified_at", "verification_required",
            "verification_record_name", "verification_record_value", "scans_allowed",
            "sla_days", "scope_exclusions", "log_retention_days",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "domain_verified_at"]

    def validate_root_domain(self, value):
        value = validate_root_domain(value)
        # Changing the domain after creation would carry the old
        # domain's verification over to one that was never proven.
        if self.instance is not None and value != self.instance.root_domain:
            raise serializers.ValidationError(
                "root_domain can't be changed. Create a new organization for a different domain."
            )
        return value

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["sla_days"] = instance.sla_policy
        return data

    def validate_sla_days(self, value):
        unknown = set(value) - set(self.SLA_ORDER)
        if unknown:
            raise serializers.ValidationError(f"Unknown severity: {', '.join(sorted(unknown))}.")
        policy = {**settings.REMEDIATION_SLA_DAYS, **(self.instance.sla_days if self.instance else {}), **value}
        days = [policy[severity] for severity in self.SLA_ORDER]
        if days != sorted(days):
            raise serializers.ValidationError(
                "More serious issues need the same or less time to fix: critical <= high <= medium <= low."
            )
        return policy

    LOG_RETENTION_CHOICES = (7, 14, 30, 60, 90, 180, 365)

    def validate_log_retention_days(self, value):
        if value not in self.LOG_RETENTION_CHOICES:
            raise serializers.ValidationError(
                "Choose one of: " + ", ".join(str(days) for days in self.LOG_RETENTION_CHOICES) + " days."
            )
        return value

    def validate_scope_exclusions(self, value):
        root = self.instance.root_domain if self.instance else self.initial_data.get("root_domain", "")
        cleaned = []
        for entry in value:
            pattern = entry.strip().lower().rstrip(".")
            if not pattern:
                continue
            host = pattern[2:] if pattern.startswith("*.") else pattern
            try:
                host = validate_root_domain(host)
            except serializers.ValidationError:
                raise serializers.ValidationError(f"'{entry}' is not a host name (use *.name for everything under one).")
            if host != root and not host.endswith(f".{root}"):
                raise serializers.ValidationError(f"'{entry}' is not under {root}, so it is never scanned anyway.")
            if pattern == root:
                raise serializers.ValidationError(f"{root} itself can't be excluded; it is what the organization monitors.")
            if pattern not in cleaned:
                cleaned.append(pattern)
        return cleaned

    def get_verification_required(self, obj) -> bool:
        return settings.REQUIRE_DOMAIN_VERIFICATION

    def get_my_role(self, obj) -> str | None:
        request = self.context.get("request")
        if request is None or not request.user.is_authenticated:
            return None
        # One query per serializer, not one per organization in a list.
        if not hasattr(self, "_roles_by_org"):
            self._roles_by_org = dict(
                Membership.objects.filter(user=request.user).values_list("organization_id", "role")
            )
        if request.user.is_superuser:
            return self._roles_by_org.get(obj.id, Membership.Role.OWNER)
        return self._roles_by_org.get(obj.id)


class MembershipSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)
    # The account's id, which is what findings are assigned to.
    user_id = serializers.IntegerField(source="user.id", read_only=True)

    class Meta:
        model = Membership
        fields = ["id", "user_id", "username", "email", "role", "created_at"]
        read_only_fields = fields


class UpdateMemberSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=Membership.Role.choices)


class AddMemberSerializer(serializers.Serializer):
    """Input for POST /api/organizations/{id}/members/."""

    identifier = serializers.CharField(help_text="Username or email of an existing account.")
    role = serializers.ChoiceField(choices=Membership.Role.choices, default=Membership.Role.VIEWER)

    def validate(self, attrs):
        identifier = attrs["identifier"].strip()
        users = get_user_model().objects.filter(
            Q(username__iexact=identifier) | Q(email__iexact=identifier), is_active=True
        )
        # Two accounts can share an email; refuse to guess between them.
        if users.count() != 1:
            raise serializers.ValidationError(
                {"identifier": "No single account matches that username or email. "
                               "The person needs an account before they can be added."}
            )
        user = users.get()
        if Membership.objects.filter(user=user, organization=self.context["organization"]).exists():
            raise serializers.ValidationError(
                {"identifier": f"{user.username} is already a member of this organization."}
            )
        attrs["user"] = user
        return attrs
