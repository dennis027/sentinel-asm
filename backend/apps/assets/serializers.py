from rest_framework import serializers

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

    class Meta:
        model = Asset  
        fields = [
            "id", "organization", "organization_name", "asset_type", "value",
            "is_active", "first_seen", "last_seen", "technologies",
        ]
        read_only_fields = ["id", "first_seen", "last_seen"]


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

    class Meta:
        model = Asset
        fields = [
            "id", "organization", "organization_name", "asset_type", "value",
            "is_active", "first_seen", "last_seen", "technologies",
            "risk_score", "risk_grade",
        ]
        read_only_fields = ["id", "first_seen", "last_seen"]