from django.utils import timezone
from rest_framework import serializers

from .compliance import controls_for
from .guidance import guidance_for
from .kev import known_exploited
from .models import Finding, FindingComment, SurfacePolicy
from .remediation import due_at, is_overdue


class FindingSerializer(serializers.ModelSerializer):
    asset_value = serializers.CharField(source="asset.value", read_only=True)
    status_changed_by = serializers.CharField(
        source="status_changed_by.username", read_only=True, default=None
    )

    # Why this matters and what to do about it, in plain language --
    # see guidance.py. Empty for inventory findings.
    impact = serializers.SerializerMethodField()
    remediation = serializers.SerializerMethodField()
    # Remediation workflow: who owns it and when it should be fixed by.
    assignee_username = serializers.CharField(source="assignee.username", read_only=True, default=None)
    due_at = serializers.SerializerMethodField()
    overdue = serializers.SerializerMethodField()
    # Frameworks this kind of issue relates to (indicative -- see compliance.py).
    controls = serializers.SerializerMethodField()
    # How much the host matters to the business (set on the asset).
    asset_criticality = serializers.CharField(source="asset.criticality", read_only=True)
    # Set when one of the finding's CVEs is in CISA's known-exploited catalogue.
    known_exploited = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = [
            "id", "asset", "asset_value", "finding_type", "severity",
            "title", "description", "impact", "remediation", "raw_data", "is_active",
            "status", "status_note", "status_changed_at", "status_changed_by",
            "first_seen", "last_seen", "resolved_at",
            "assignee", "assignee_username", "due_at", "overdue", "controls",
            "accepted_until", "reopened_count", "reopened_at", "asset_criticality", "cves", "known_exploited",
        ]
        read_only_fields = fields

    def get_impact(self, obj) -> str:
        return guidance_for(obj)["impact"]

    def get_remediation(self, obj) -> str:
        return guidance_for(obj)["remediation"]

    def get_due_at(self, obj):
        if obj.finding_type in Finding.INVENTORY_TYPES:
            return None
        deadline = due_at(obj)
        return deadline.isoformat() if deadline else None

    def get_overdue(self, obj) -> bool:
        return obj.finding_type not in Finding.INVENTORY_TYPES and is_overdue(obj)

    def get_known_exploited(self, obj) -> dict | None:
        return known_exploited(obj.cves)

    def get_controls(self, obj) -> list[dict]:
        if obj.finding_type in Finding.INVENTORY_TYPES:
            return []
        return controls_for(obj.finding_type)


class FindingAssignSerializer(serializers.Serializer):
    """Input for POST /api/findings/{id}/assign/. Null clears the assignee."""

    assignee = serializers.IntegerField(allow_null=True)


class FindingTriageSerializer(serializers.Serializer):
    """Input for POST /api/findings/{id}/triage/ (and the bulk version)."""

    status = serializers.ChoiceField(choices=Finding.Status.choices)
    note = serializers.CharField(required=False, allow_blank=True, default="")
    # Only with status "accepted": the date the acceptance runs out and
    # the finding opens again. Leave out for an open-ended acceptance.
    accepted_until = serializers.DateField(required=False, allow_null=True, default=None)

    def validate(self, attrs):
        until = attrs.get("accepted_until")
        if until is not None:
            if attrs["status"] != Finding.Status.ACCEPTED:
                raise serializers.ValidationError(
                    {"accepted_until": ["Only an accepted risk can have an end date."]}
                )
            if until <= timezone.localdate():
                raise serializers.ValidationError({"accepted_until": ["Choose a date in the future."]})
        return attrs


class FindingBulkSerializer(serializers.Serializer):
    """
    Input for POST /api/findings/bulk/: one action on many findings.
    action "triage" takes the triage fields; action "assign" takes `assignee`.
    """

    MAX_FINDINGS = 500

    ids = serializers.ListField(child=serializers.UUIDField(), min_length=1, max_length=MAX_FINDINGS)
    action = serializers.ChoiceField(choices=[("triage", "Triage"), ("assign", "Assign")])
    status = serializers.ChoiceField(choices=Finding.Status.choices, required=False)
    note = serializers.CharField(required=False, allow_blank=True, default="")
    accepted_until = serializers.DateField(required=False, allow_null=True, default=None)
    assignee = serializers.IntegerField(required=False, allow_null=True)

    def validate(self, attrs):
        if attrs["action"] == "triage":
            if "status" not in attrs:
                raise serializers.ValidationError({"status": ["Choose what to mark them as."]})
            FindingTriageSerializer(data={
                "status": attrs["status"], "note": attrs["note"], "accepted_until": attrs["accepted_until"],
            }).is_valid(raise_exception=True)
        elif "assignee" not in attrs:
            raise serializers.ValidationError({"assignee": ["Choose who to assign them to, or null for nobody."]})
        return attrs


class FindingCommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = FindingComment
        fields = ["id", "author_name", "body", "created_at"]
        read_only_fields = ["id", "author_name", "created_at"]

    def validate_body(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Write something first.")
        return value


class SurfacePolicySerializer(serializers.ModelSerializer):
    kind_label = serializers.CharField(source="get_kind_display", read_only=True)
    rule = serializers.CharField(read_only=True)
    # Hosts breaking it right now (counted by the view).
    breaking = serializers.SerializerMethodField()

    class Meta:
        model = SurfacePolicy
        fields = [
            "id", "organization", "name", "kind", "kind_label", "value", "severity", "guidance",
            "enabled", "rule", "breaking", "created_at",
        ]
        read_only_fields = ["id", "created_at"]

    def get_breaking(self, obj) -> int:
        return self.context.get("breaking", {}).get(str(obj.id), 0)

    def validate(self, attrs):
        kind = attrs.get("kind", getattr(self.instance, "kind", None))
        value = str(attrs.get("value", getattr(self.instance, "value", ""))).strip()
        if kind == SurfacePolicy.Kind.PORT:
            if not value.isdigit() or not 1 <= int(value) <= 65535:
                raise serializers.ValidationError({"value": ["Enter a port number from 1 to 65535."]})
            value = str(int(value))
        elif kind == SurfacePolicy.Kind.HOSTNAME:
            value = value.lower()
            if not value or " " in value:
                raise serializers.ValidationError({"value": ["Enter a name pattern such as *dev* or staging.*"]})
        elif not value:
            raise serializers.ValidationError({"value": ["Say what the policy is about."]})
        if "value" in attrs or self.instance is None:
            attrs["value"] = value
        if self.instance is not None and "organization" in attrs and attrs["organization"] != self.instance.organization:
            raise serializers.ValidationError({"organization": ["A policy can't move to another organization."]})
        return attrs

