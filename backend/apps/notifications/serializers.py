from urllib.parse import urlsplit

from rest_framework import serializers

from apps.scanning.targets import TargetNotAllowed, assert_public_target

from .models import NotificationRule


class NotificationRuleSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)

    class Meta:
        model = NotificationRule
        fields = [
            "id", "organization", "organization_name", "channel",
            "recipient_email", "webhook_url", "min_severity", "is_active", "weekly_report", "created_at",
        ]
        read_only_fields = ["id", "created_at"]
        # Replaced by the friendlier check in validate() below.
        validators = []

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # A webhook link works like a password for posting into that
        # channel: only people who can manage alerts see all of it.
        if data.get("webhook_url") and not self._can_manage(instance):
            parts = urlsplit(data["webhook_url"])
            data["webhook_url"] = f"{parts.scheme}://{parts.hostname}/…"
        return data

    def _can_manage(self, instance) -> bool:
        from apps.organizations.models import Membership

        request = self.context.get("request")
        if request is None:
            return True
        if request.user.is_superuser:
            return True
        if not hasattr(self, "_roles"):
            self._roles = dict(Membership.objects.filter(user=request.user).values_list("organization_id", "role"))
        role = self._roles.get(instance.organization_id)
        return role is not None and Membership.ROLE_RANK[role] >= Membership.ROLE_RANK[Membership.Role.ADMIN]

    def validate_organization(self, value):
        # A rule stays in the organization it was created for. Letting
        # an update move it would let a member of one org re-point their
        # rule at another org and receive that org's findings by email.
        if self.instance is not None and value != self.instance.organization:
            raise serializers.ValidationError("A rule can't be moved to another organization.")
        return value

    def validate(self, attrs):
        def current(field, default=""):
            return attrs.get(field, getattr(self.instance, field, default) if self.instance else default)

        channel = current("channel", NotificationRule.Channel.EMAIL)
        if channel == NotificationRule.Channel.WEBHOOK:
            attrs["recipient_email"] = ""
            # The weekly report is a PDF attachment; webhooks can't carry it.
            attrs["weekly_report"] = False
            url = current("webhook_url")
            if not url:
                raise serializers.ValidationError({"webhook_url": "Enter the webhook address."})
            parts = urlsplit(url)
            if parts.scheme != "https":
                raise serializers.ValidationError({"webhook_url": "The webhook address must start with https://"})
            # The server will be POSTing to this address; it must not be
            # a way to reach the platform's own network.
            try:
                assert_public_target(parts.hostname or "")
            except TargetNotAllowed:
                raise serializers.ValidationError(
                    {"webhook_url": "The webhook address must be a public internet address."}
                )
        else:
            attrs["webhook_url"] = ""
            if not current("recipient_email"):
                raise serializers.ValidationError({"recipient_email": "Enter an email address."})

        duplicate = NotificationRule.objects.filter(
            organization=current("organization", None),
            recipient_email=attrs.get("recipient_email", current("recipient_email")),
            webhook_url=attrs.get("webhook_url", current("webhook_url")),
        )
        if self.instance is not None:
            duplicate = duplicate.exclude(pk=self.instance.pk)
        if duplicate.exists():
            raise serializers.ValidationError("There is already a rule for this destination.")
        return attrs
