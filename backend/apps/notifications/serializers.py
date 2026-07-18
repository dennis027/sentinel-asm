from rest_framework import serializers

from .models import NotificationRule


class NotificationRuleSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)

    class Meta:
        model = NotificationRule
        fields = [
            "id", "organization", "organization_name",
            "recipient_email", "min_severity", "is_active", "created_at",
        ]
        read_only_fields = ["id", "created_at"]