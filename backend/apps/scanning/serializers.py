from rest_framework import serializers

from apps.assets.models import Asset
from apps.organizations.models import Organization

from .models import ScanJob
from .plugins.registry import list_scanners


class ScanJobSerializer(serializers.ModelSerializer):
    asset_value = serializers.CharField(source="asset.value", read_only=True, default=None)
    organization_name = serializers.CharField(source="organization.name", read_only=True)

    class Meta:
        model = ScanJob
        fields = [
            "id", "organization", "organization_name", "asset", "asset_value",
            "scanner_name", "status", "error_message",
            "created_at", "started_at", "finished_at",
        ]
        read_only_fields = fields


class ScanJobTriggerSerializer(serializers.Serializer):
    """
    Input-only serializer for POST /api/scan-jobs/trigger/.
    Not a ModelSerializer -- this never represents a ScanJob directly,
    it validates the request and the view creates the ScanJob itself.
    """

    scanner_name = serializers.CharField()
    asset_id = serializers.UUIDField(required=False)
    organization_id = serializers.UUIDField(required=False)

    def validate_scanner_name(self, value):
        registered = list_scanners()
        if value not in registered:
            raise serializers.ValidationError(
                f"Unknown scanner '{value}'. Registered scanners: {registered}"
            )
        return value

    def validate(self, attrs):
        if not attrs.get("asset_id") and not attrs.get("organization_id"):
            raise serializers.ValidationError(
                "Provide either asset_id (for asset-level scanners) or "
                "organization_id (for org-level scanners like subdomain discovery)."
            )
        if attrs.get("asset_id"):
            try:
                attrs["asset"] = Asset.objects.select_related("organization").get(id=attrs["asset_id"])
                attrs["organization"] = attrs["asset"].organization
            except Asset.DoesNotExist:
                raise serializers.ValidationError({"asset_id": "No asset with this id."})
        else:
            attrs["asset"] = None
            try:
                attrs["organization"] = Organization.objects.get(id=attrs["organization_id"])
            except Organization.DoesNotExist:
                raise serializers.ValidationError({"organization_id": "No organization with this id."})
        return attrs