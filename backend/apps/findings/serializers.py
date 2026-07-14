from rest_framework import serializers

from .models import Finding


class FindingSerializer(serializers.ModelSerializer):
    asset_value = serializers.CharField(source="asset.value", read_only=True)

    class Meta:
        model = Finding
        fields = [
            "id", "asset", "asset_value", "finding_type", "severity",
            "title", "description", "raw_data", "is_active",
            "first_seen", "last_seen",
        ]
        read_only_fields = fields