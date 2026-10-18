from rest_framework import serializers

from apps.organizations.models import Organization

from datetime import timedelta

from django.utils import timezone

from .models import ErrorGroup, LogAlertRule, LogDetection, LogEvent, LogSource


class LogSourceSerializer(serializers.ModelSerializer):
    status = serializers.CharField(read_only=True)
    is_application = serializers.BooleanField(read_only=True)
    open_detections = serializers.IntegerField(read_only=True, default=0)

    class Meta:
        model = LogSource
        fields = [
            "id", "organization", "name", "os", "key_prefix", "created_at", "last_seen_at", "last_host",
            "events_received", "status", "is_application", "open_detections",
        ]
        read_only_fields = ["id", "key_prefix", "created_at", "last_seen_at", "last_host", "events_received"]

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Give the server a name, such as web-01.")
        return value

    def validate(self, attrs):
        organization = attrs.get("organization") or getattr(self.instance, "organization", None)
        name = attrs.get("name")
        if organization and name:
            clash = LogSource.objects.filter(organization=organization, name__iexact=name)
            if self.instance:
                clash = clash.exclude(pk=self.instance.pk)
            if clash.exists():
                raise serializers.ValidationError({"name": "There is already a server with this name."})
        return attrs


class LogEventSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)
    category_label = serializers.CharField(source="get_category_display", read_only=True)

    class Meta:
        model = LogEvent
        fields = [
            "id", "source", "source_name", "occurred_at", "received_at", "host", "program", "event_id",
            "level", "category", "category_label", "action", "user", "src_ip", "message", "raw",
            "service", "http_status", "fingerprint", "redacted", "release",
        ]
        read_only_fields = fields


class LogDetectionSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)
    resolved_by = serializers.CharField(source="resolved_by.username", read_only=True, default=None)

    class Meta:
        model = LogDetection
        fields = [
            "id", "source", "source_name", "rule", "severity", "title", "description", "user", "src_ip",
            "event_count", "first_seen", "last_seen", "status", "resolved_at", "resolved_by",
        ]
        read_only_fields = fields


class OrganizationRef(serializers.Serializer):
    organization = serializers.PrimaryKeyRelatedField(queryset=Organization.objects.all())


class ErrorGroupSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)

    class Meta:
        model = ErrorGroup
        fields = [
            "id", "source", "source_name", "fingerprint", "exception_type", "title", "culprit", "service", "count",
            "first_seen", "last_seen", "stacktrace", "status", "resolved_at", "regressions", "first_release",
            "last_release",
        ]
        read_only_fields = fields


MAX_RULES_PER_ORGANIZATION = 50
SEVERITIES = ("low", "medium", "high", "critical")


class LogAlertRuleSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True, default=None)
    created_by = serializers.CharField(source="created_by.username", read_only=True, default=None)
    matches_24h = serializers.SerializerMethodField()

    class Meta:
        model = LogAlertRule
        fields = [
            "id", "organization", "name", "contains", "source", "source_name", "category", "level", "threshold",
            "window_minutes", "severity", "enabled", "created_by", "created_at", "last_fired_at", "matches_24h",
        ]
        read_only_fields = ["id", "created_by", "created_at", "last_fired_at"]
        extra_kwargs = {"organization": {"required": True}}

    def get_matches_24h(self, rule) -> int:
        return rule.events().filter(occurred_at__gte=timezone.now() - timedelta(hours=24)).count()

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Give the alert a name, such as \"Payments declined\".")
        return value

    def validate_contains(self, value):
        return value.strip()

    def validate_threshold(self, value):
        if not 1 <= value <= 100_000:
            raise serializers.ValidationError("Between 1 and 100,000.")
        return value

    def validate_window_minutes(self, value):
        if not 1 <= value <= 1440:
            raise serializers.ValidationError("Between 1 minute and 24 hours (1440).")
        return value

    def validate_severity(self, value):
        if value not in SEVERITIES:
            raise serializers.ValidationError("Choose low, medium, high or critical.")
        return value

    def validate(self, attrs):
        organization = attrs.get("organization") or getattr(self.instance, "organization", None)
        if self.instance and "organization" in attrs and attrs["organization"] != self.instance.organization:
            raise serializers.ValidationError({"organization": "An alert can't move to another organization."})
        source = attrs.get("source", getattr(self.instance, "source", None))
        if source and organization and source.organization_id != organization.id:
            raise serializers.ValidationError({"source": "Choose one of this organization's servers or apps."})
        contains = attrs.get("contains", getattr(self.instance, "contains", ""))
        category = attrs.get("category", getattr(self.instance, "category", ""))
        if not contains and not category:
            raise serializers.ValidationError(
                {"contains": "Say what to look for: some text, a kind of event, or both."}
            )
        if not self.instance and organization and (
            LogAlertRule.objects.filter(organization=organization).count() >= MAX_RULES_PER_ORGANIZATION
        ):
            raise serializers.ValidationError(f"An organization can have up to {MAX_RULES_PER_ORGANIZATION} alerts.")
        return attrs
