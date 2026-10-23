from rest_framework import serializers

from apps.organizations.models import Organization

from .models import Asset, Technology


class TechnologySerializer(serializers.ModelSerializer):
    class Meta:
        model = Technology
        fields = ["id", "name", "version", "category", "first_seen", "last_seen"]
        read_only_fields = fields


class AssetSerializer(serializers.ModelSerializer):
    # Nested read-only: an Asset's technologies are populated by the httpx
    # scanner, never edited directly through this endpoint.
    technologies = TechnologySerializer(many=True, read_only=True)
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    # Computed from active findings on every request -- see
    # Asset.risk_score / apps.findings.risk_scoring. Not stored, so it's
    # always current, no staleness/cache-invalidation to worry about.
    risk_score = serializers.IntegerField(read_only=True)
    risk_grade = serializers.CharField(read_only=True)
    # On the organization's never-scan list.
    out_of_scope = serializers.SerializerMethodField()
    owner_name = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = [
            "id", "organization", "organization_name", "asset_type", "value", "source",
            "is_active", "first_seen", "last_seen", "technologies",
            "risk_score", "risk_grade", "criticality", "tags", "out_of_scope",
            "owner", "owner_name", "web", "hosting",
        ]
        read_only_fields = ["id", "first_seen", "last_seen"]

    def get_out_of_scope(self, obj) -> bool:
        return obj.organization.is_out_of_scope(obj.value)

    def get_owner_name(self, obj) -> str | None:
        if obj.owner is None:
            return None
        return obj.owner.get_full_name() or obj.owner.username


class AssetUpdateSerializer(serializers.ModelSerializer):
    """Input for PATCH /api/assets/{id}/: the business context people add."""

    MAX_TAGS = 10

    class Meta:
        model = Asset
        fields = ["criticality", "tags", "owner"]

    def validate_owner(self, value):
        if value is not None and not self.instance.organization.memberships.filter(user=value).exists():
            raise serializers.ValidationError("The owner must be a member of this organization.")
        return value

    def validate_tags(self, value):
        if not isinstance(value, list) or not all(isinstance(tag, str) for tag in value):
            raise serializers.ValidationError("Send a list of short labels.")
        tags = []
        for tag in value:
            tag = "-".join(tag.strip().lower().split())
            if not tag:
                continue
            if len(tag) > 30:
                raise serializers.ValidationError(f"'{tag}' is too long; keep labels under 30 characters.")
            if tag not in tags:
                tags.append(tag)
        if len(tags) > self.MAX_TAGS:
            raise serializers.ValidationError(f"Use at most {self.MAX_TAGS} labels.")
        return tags


class AssetBulkCreateSerializer(serializers.Serializer):
    """Input for POST /api/assets/bulk/: many host names at once, one per line or as a list."""

    MAX_VALUES = 500

    organization = serializers.PrimaryKeyRelatedField(queryset=Organization.objects.all())
    values = serializers.ListField(child=serializers.CharField(max_length=512, allow_blank=True), max_length=MAX_VALUES)

class AssetCreateSerializer(serializers.ModelSerializer):
    """Input for adding an asset by hand (POST /api/assets/)."""

    class Meta:
        model = Asset
        fields = ["organization", "value"]
        validators = []

    def validate(self, attrs):
        from apps.scanning.targets import validate_root_domain

        organization = attrs["organization"]
        value = attrs["value"].strip().lower().rstrip(".")
        try:
            value = validate_root_domain(value)
        except serializers.ValidationError:
            raise serializers.ValidationError({"value": ["Enter a host name such as vpn.example.com."]})

        root = organization.root_domain
        if value != root and not value.endswith(f".{root}"):
            raise serializers.ValidationError(
                {"value": [f"Assets must be {root} or a name under it, like vpn.{root}."]}
            )
        if Asset.objects.filter(organization=organization, value=value).exists():
            raise serializers.ValidationError({"value": [f"{value} is already being monitored."]})

        attrs["value"] = value
        attrs["asset_type"] = Asset.AssetType.DOMAIN if value == root else Asset.AssetType.SUBDOMAIN
        attrs["source"] = Asset.Source.MANUAL
        return attrs
