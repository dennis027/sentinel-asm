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
    force = serializers.BooleanField(
        default=False,
        help_text=(
            "If true, always start a brand-new scan even if the same "
            "scanner already ran against this target today. If false "
            "(default), retriggering the same scan same-day returns the "
            "existing job instead of duplicating it."
        ),
    )

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
                "Provide organization_id to run the scanner for the whole domain, "
                "or asset_id to run it on one asset."
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


class DomainScanStartedSerializer(serializers.Serializer):
    """Response when a scanner is started for a whole organization."""

    batch_id = serializers.UUIDField()
    scanner_name = serializers.CharField()
    target_count = serializers.IntegerField(help_text="How many scans this run will perform.")


class ScanProgressSerializer(serializers.Serializer):
    """Where one scanner's most recent domain-wide run stands."""

    scanner_name = serializers.CharField()
    batch_id = serializers.UUIDField()
    started_at = serializers.DateTimeField()
    total = serializers.IntegerField()
    pending = serializers.IntegerField()
    running = serializers.IntegerField()
    success = serializers.IntegerField()
    failed = serializers.IntegerField()
    finished = serializers.BooleanField()


class ScannerInfoSerializer(serializers.Serializer):
    """
    Read-only representation of a registered scanner plugin, for the
    frontend's "Scanners" tab -- lets the UI build the trigger form
    (which scanners exist, what they target, what they detect) without
    hardcoding a scanner list that would drift from the backend.
    """

    name = serializers.CharField()
    label = serializers.CharField()
    description = serializers.CharField(allow_blank=True)
    category = serializers.CharField()
    applies_to = serializers.CharField()
    owned_finding_types = serializers.ListField(child=serializers.CharField())