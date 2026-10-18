"""
Thin, mostly-read viewsets over the core models. The only real write
action is `trigger` on ScanJobViewSet -- everything else (Organization,
Asset, Finding) is populated by scanners, not by API clients.

Every viewset below mixes in OrgScopedQuerysetMixin: IsAuthenticated
alone (DRF's default) proves WHO a caller is, not WHICH organization's
data they're allowed to see -- without this, any logged-in user could
list/read every other tenant's assets and findings. See
apps/api/permissions.py for the actual filtering logic.
"""

import uuid
from datetime import timedelta

from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.db.models import Count, F, Max, Min, Q
from django.http import FileResponse, Http404, HttpResponse
from django.utils import timezone
import django_filters
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import filters, mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.assets.models import Asset
from apps.assets.serializers import (
    AssetBulkCreateSerializer,
    AssetCreateSerializer,
    AssetSerializer,
    AssetUpdateSerializer,
)
from apps.assets.utils import ensure_root_domain_asset
from apps.findings.filters import FindingFilter
from apps.findings.models import Finding
from apps.findings.reports import generate_csv, generate_executive_report, generate_json, generate_pdf
from apps.findings.compliance import build_compliance
from apps.findings.insights import (
    build_certificates,
    build_fix_plan,
    build_heatmap,
    build_services,
    build_technologies,
)
from apps.findings.remediation import remediation_metrics
from apps.findings.summary import (
    assets_at_risk,
    build_changes,
    build_narrative,
    build_risk_summary,
    build_trend,
    record_snapshot,
)
from apps.audit_logs.activity import record as record_activity
from apps.audit_logs.models import ActivityEvent
from apps.findings.serializers import (
    FindingAssignSerializer,
    FindingBulkSerializer,
    FindingCommentSerializer,
    FindingSerializer,
    FindingTriageSerializer,
)
from apps.notifications.models import NotificationRule
from apps.notifications.tasks import send_test_alert, send_weekly_report
from apps.notifications.serializers import NotificationRuleSerializer
from apps.organizations.models import Membership, Organization
from apps.organizations.deletion import delete_organization
from apps.organizations.serializers import (
    AddMemberSerializer,
    MembershipSerializer,
    OrganizationSerializer,
    UpdateMemberSerializer,
)
from apps.organizations.verification import has_verification_record
from apps.scanning import screenshot_store
from apps.scanning.models import ScanJob
from apps.scanning.plugins.registry import get_scanner, list_scanners
from apps.scanning.serializers import (
    DomainScanStartedSerializer,
    ScanJobSerializer,
    ScanJobTriggerSerializer,
    ScannerInfoSerializer,
    ScanProgressSerializer,
    person,
)
from apps.scanning.tasks import domain_scan_lock_key, fan_out_domain_scan, run_scan_job

from .permissions import OrgScopedQuerysetMixin, require_org_role, user_can_access_org

User = get_user_model()

class OrganizationViewSet(OrgScopedQuerysetMixin, viewsets.ModelViewSet):
    """
    Full CRUD -- upgraded from read-only so a user can self-service
    create their own organization (standard "create your workspace"
    SaaS pattern). Creating one automatically makes the creator its
    Owner (see perform_create) -- otherwise a freshly created org
    would be invisible to everyone, including its own creator, the
    instant org-scoping is applied.
    """

    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["name", "root_domain"]
    org_field = "pk"  # the model IS Organization -- filter by its own id

    def perform_create(self, serializer):
        organization = serializer.save()
        Membership.objects.create(
            user=self.request.user, organization=organization, role=Membership.Role.OWNER
        )
        ensure_root_domain_asset(organization)
        record_activity(
            self.request.user, organization, ActivityEvent.Verb.ORG_CREATED,
            f"Created {organization.name} for {organization.root_domain}",
        )

    def perform_update(self, serializer):
        require_org_role(self.request.user, serializer.instance, Membership.Role.ADMIN)
        scope_before = list(serializer.instance.scope_exclusions)
        sla_before = serializer.instance.sla_policy
        organization = serializer.save()
        if organization.scope_exclusions != scope_before:
            excluded = ", ".join(organization.scope_exclusions) or "nothing"
            record_activity(
                self.request.user, organization, ActivityEvent.Verb.SCOPE_CHANGED,
                f"Set the hosts never to scan to: {excluded}",
            )
        if organization.sla_policy != sla_before:
            policy = organization.sla_policy
            record_activity(
                self.request.user, organization, ActivityEvent.Verb.ORG_UPDATED,
                "Set the days to fix to "
                + ", ".join(f"{severity} {policy[severity]}" for severity in ("critical", "high", "medium", "low")),
            )
        elif organization.scope_exclusions == scope_before:
            record_activity(
                self.request.user, organization, ActivityEvent.Verb.ORG_UPDATED, f"Updated {organization.name}'s settings"
            )

    def perform_destroy(self, instance):
        """
        DELETE /api/organizations/{id}/ -- Owner only. Removes the
        organization and everything that belongs to it: assets,
        findings, scan history, notification rules, memberships, and
        the screenshot files on disk. There is no undo.
        """
        require_org_role(self.request.user, instance, Membership.Role.OWNER)
        delete_organization(instance)

    @extend_schema(methods=["get"], responses={200: MembershipSerializer(many=True)})
    @extend_schema(methods=["post"], request=AddMemberSerializer, responses={201: MembershipSerializer})
    @action(detail=True, methods=["get", "post"], pagination_class=None)
    def members(self, request, pk=None):
        """
        GET  /api/organizations/{id}/members/   -- anyone in the org
        POST /api/organizations/{id}/members/   -- Admin or higher
        Body: {"identifier": "<username or email>", "role": "viewer"}

        Adds an EXISTING user account to the organization. There is no
        invitation email; the person needs an account first.
        """
        organization = self.get_object()

        if request.method == "GET":
            memberships = organization.memberships.select_related("user").order_by("user__username")
            return Response(MembershipSerializer(memberships, many=True).data)

        require_org_role(request.user, organization, Membership.Role.ADMIN)
        serializer = AddMemberSerializer(data=request.data, context={"organization": organization})
        serializer.is_valid(raise_exception=True)
        self._require_owner_to_grant_owner(organization, serializer.validated_data["role"])

        membership = Membership.objects.create(
            user=serializer.validated_data["user"],
            organization=organization,
            role=serializer.validated_data["role"],
        )
        record_activity(
            request.user, organization, ActivityEvent.Verb.MEMBER_ADDED,
            f"Added {membership.user.username} as {membership.get_role_display()}",
        )
        return Response(MembershipSerializer(membership).data, status=status.HTTP_201_CREATED)

    @extend_schema(methods=["patch"], request=UpdateMemberSerializer, responses={200: MembershipSerializer})
    @extend_schema(methods=["delete"], responses={204: None})
    @action(
        detail=True, methods=["patch", "delete"],
        url_path=r"members/(?P<membership_id>[0-9a-f-]{36})",
    )
    def member(self, request, pk=None, membership_id=None):
        """
        PATCH  /api/organizations/{id}/members/{membership_id}/  {"role": "analyst"}
        DELETE /api/organizations/{id}/members/{membership_id}/

        Admin or higher, with two guards: only an Owner can grant or
        take away the Owner role, and an organization can never be left
        without one. Anyone can remove THEMSELVES (leave), subject to
        the same last-owner rule.
        """
        organization = self.get_object()
        membership = organization.memberships.select_related("user").filter(id=membership_id).first()
        if membership is None:
            raise Http404

        leaving = request.method == "DELETE" and membership.user_id == request.user.id
        if not leaving:
            require_org_role(request.user, organization, Membership.Role.ADMIN)
            self._require_owner_to_grant_owner(organization, membership.role)

        new_role = None
        if request.method == "PATCH":
            serializer = UpdateMemberSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            new_role = serializer.validated_data["role"]
            self._require_owner_to_grant_owner(organization, new_role)

        is_last_owner = (
            membership.role == Membership.Role.OWNER
            and new_role != Membership.Role.OWNER
            and organization.memberships.filter(role=Membership.Role.OWNER).count() == 1
        )
        if is_last_owner:
            return Response(
                {"detail": "An organization needs at least one owner. Make someone else an owner first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if request.method == "DELETE":
            membership.delete()
            record_activity(
                request.user, organization, ActivityEvent.Verb.MEMBER_REMOVED,
                "Left the organization" if leaving else f"Removed {membership.user.username}",
            )
            return Response(status=status.HTTP_204_NO_CONTENT)

        membership.role = new_role
        membership.save(update_fields=["role"])
        record_activity(
            request.user, organization, ActivityEvent.Verb.MEMBER_ROLE_CHANGED,
            f"Made {membership.user.username} {membership.get_role_display()}",
        )
        return Response(MembershipSerializer(membership).data)

    def _require_owner_to_grant_owner(self, organization, role) -> None:
        if role == Membership.Role.OWNER:
            require_org_role(self.request.user, organization, Membership.Role.OWNER)

    @extend_schema(request=None, responses={200: OrganizationSerializer})
    @action(detail=True, methods=["post"], url_path="verify-domain")
    def verify_domain(self, request, pk=None):
        """
        POST /api/organizations/{id}/verify-domain/
        Looks up the TXT record named in `verification_record_name` and
        marks the domain verified if it holds `verification_record_value`.
        Until then (when REQUIRE_DOMAIN_VERIFICATION is on) no scan can
        be triggered for this organization.
        """
        organization = self.get_object()
        require_org_role(request.user, organization, Membership.Role.ADMIN)

        if not organization.is_domain_verified:
            if not has_verification_record(organization):
                return Response(
                    {
                        "detail": (
                            f"No TXT record with value '{organization.verification_record_value}' "
                            f"found at {organization.verification_record_name}. DNS changes can "
                            f"take a few minutes to propagate."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            organization.domain_verified_at = timezone.now()
            organization.save(update_fields=["domain_verified_at", "updated_at"])
            record_activity(
                request.user, organization, ActivityEvent.Verb.DOMAIN_VERIFIED,
                f"Verified ownership of {organization.root_domain}",
            )

        return Response(self.get_serializer(organization).data)

    @extend_schema(
        parameters=[
            OpenApiParameter("export_format", OpenApiTypes.STR, enum=["csv", "json", "pdf"], default="csv"),
            OpenApiParameter("severity", OpenApiTypes.STR, required=False),
            OpenApiParameter("finding_type", OpenApiTypes.STR, required=False),
            OpenApiParameter("is_active", OpenApiTypes.BOOL, required=False),
        ],
        responses={200: OpenApiTypes.BINARY},
    )
    @action(detail=True, methods=["get"], url_path="export")
    def export(self, request, pk=None):
        """
        GET /api/organizations/{id}/export/?export_format=csv|json|pdf
        Optional filters: severity, finding_type, is_active (same
        semantics as GET /api/findings/).

        Uses get_object() (already org-scoped via the mixin) so this
        can't be used to export another organization's findings just
        by changing the URL's id.
        """
        organization = self.get_object()
        # NOT named "format" -- that's DRF's own reserved query param for
        # content-negotiation (?format=json forces the JSON renderer,
        # etc). Using it here would silently 404 before this view even
        # runs, since DRF tries to find a renderer for "csv"/"pdf" and
        # fails.
        export_format = request.query_params.get("export_format", "csv").lower()
        if export_format not in ("csv", "json", "pdf"):
            return Response(
                {"export_format": ["Must be one of: csv, json, pdf."]}, status=status.HTTP_400_BAD_REQUEST
            )

        findings = Finding.objects.filter(asset__organization=organization).select_related("asset")
        if severity := request.query_params.get("severity"):
            findings = findings.filter(severity=severity)
        if finding_type := request.query_params.get("finding_type"):
            findings = findings.filter(finding_type=finding_type)
        if (is_active := request.query_params.get("is_active")) is not None:
            findings = findings.filter(is_active=is_active.lower() == "true")

        findings = list(findings.by_severity())
        filename_base = f"{organization.root_domain}-findings-{timezone.now().strftime('%Y%m%d')}"

        if export_format == "csv":
            content = generate_csv(findings)
            content_type = "text/csv"
        elif export_format == "json":
            content = generate_json(findings)
            content_type = "application/json"
        else:
            content = generate_pdf(findings, organization.name)
            content_type = "application/pdf"

        response = HttpResponse(content, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{filename_base}.{export_format}"'
        return response

    @action(detail=True, methods=["get"], url_path="risk-summary")
    def risk_summary(self, request, pk=None):
        """
        GET /api/organizations/{id}/risk-summary/
        The organization's headline numbers -- see
        apps.findings.summary.build_risk_summary for how the grade works.
        """
        organization = self.get_object()  # already org-scoped -- 404s if not a member
        summary = build_risk_summary(organization)
        # Every look at the numbers also records today's point on the trend.
        record_snapshot(organization, summary)
        remediation = remediation_metrics(organization)
        summary["remediation"] = remediation
        summary["narrative"] = build_narrative(
            organization, summary, build_changes(organization, 7), remediation, build_trend(organization, 90)
        )
        return Response(summary)

    @extend_schema(
        parameters=[OpenApiParameter("days", OpenApiTypes.INT, default=30, description="7 to 365")],
    )
    @action(detail=True, methods=["get"])
    def trend(self, request, pk=None):
        """
        GET /api/organizations/{id}/trend/?days=30
        One point per day that the numbers were recorded: score, grade,
        open issues. Shows whether things are getting better or worse.
        """
        organization = self.get_object()
        try:
            days = min(365, max(7, int(request.query_params.get("days", 30))))
        except ValueError:
            days = 30
        return Response({"days": days, "points": build_trend(organization, days)})

    @action(detail=True, methods=["get"])
    def compliance(self, request, pk=None):
        """
        GET /api/organizations/{id}/compliance/
        Open issues grouped by the framework controls they relate to
        (OWASP Top 10, CIS Controls, ISO 27001, PCI DSS). Indicative only.
        """
        return Response(build_compliance(self.get_object()))

    @action(detail=True, methods=["get"])
    def activity(self, request, pk=None):
        """
        GET /api/organizations/{id}/activity/
        The organization's audit trail, newest first. Any member can read it.
        """
        organization = self.get_object()
        page = self.paginate_queryset(organization.activity.all())
        rows = [
            {
                "id": event.id,
                "actor": event.actor_name,
                "verb": event.verb,
                "summary": event.summary,
                "created_at": event.created_at,
            }
            for event in page
        ]
        return self.get_paginated_response(rows)

    SURFACE_MAP_LIMIT = 60

    @action(detail=True, methods=["get"], url_path="surface-map")
    def surface_map(self, request, pk=None):
        """
        GET /api/organizations/{id}/surface-map/
        The data behind the attack surface map: the root domain and up
        to 60 assets around it -- every asset with open issues first
        (worst first), then clean ones to fill the picture.
        """
        organization = self.get_object()
        risky = assets_at_risk(organization)
        nodes = [{**asset, "clean": False} for asset in risky[: self.SURFACE_MAP_LIMIT]]
        room = self.SURFACE_MAP_LIMIT - len(nodes)
        if room > 0:
            shown = {asset["id"] for asset in nodes}
            for asset_id, value in (
                organization.assets.filter(is_active=True)
                .exclude(id__in=shown)
                .order_by("value")
                .values_list("id", "value")[:room]
            ):
                nodes.append({
                    "id": asset_id, "value": value, "risk_score": 100, "risk_grade": "A+",
                    "open_findings": 0, "critical_high": 0, "clean": True,
                })
        total = organization.assets.filter(is_active=True).count()
        return Response({
            "root_domain": organization.root_domain,
            "total_assets": total,
            "assets_at_risk": len(risky),
            "nodes": nodes,
            "hidden": max(0, total - len(nodes)),
        })

    @action(detail=True, methods=["get"], url_path="fix-plan")
    def fix_plan(self, request, pk=None):
        """
        GET /api/organizations/{id}/fix-plan/
        Open issues grouped into the actions that fix them, most urgent
        first, each with the grade the organization would have once it
        (and every step before it) is done.
        """
        return Response(build_fix_plan(self.get_object()))

    @action(detail=True, methods=["get"], url_path="alert-volume")
    def alert_volume(self, request, pk=None):
        """
        GET /api/organizations/{id}/alert-volume/
        New issues found in the last 30 days, by severity -- so choosing
        an alert threshold can say "about 6 in the last month" instead of
        leaving people to guess how noisy it will be.
        """
        organization = self.get_object()
        since = timezone.now() - timedelta(days=30)
        counts = dict(
            Finding.objects.filter(asset__organization=organization, first_seen__gte=since)
            .exclude(finding_type__in=Finding.INVENTORY_TYPES)
            .values_list("severity")
            .annotate(count=Count("id"))
        )
        return Response({
            "days": 30,
            "new_issues": {severity: counts.get(severity, 0) for severity in Finding.Severity.values},
        })

    @action(detail=True, methods=["get"])
    def heatmap(self, request, pk=None):
        """GET /api/organizations/{id}/heatmap/ -- open issues by kind and severity."""
        return Response(build_heatmap(self.get_object()))

    @action(detail=True, methods=["get"])
    def technologies(self, request, pk=None):
        """GET /api/organizations/{id}/technologies/ -- software seen, with the hosts it runs on."""
        return Response(build_technologies(self.get_object()))

    @action(detail=True, methods=["get"])
    def services(self, request, pk=None):
        """GET /api/organizations/{id}/services/ -- open ports, with the hosts they are open on."""
        return Response(build_services(self.get_object()))

    @action(detail=True, methods=["get"])
    def certificates(self, request, pk=None):
        """GET /api/organizations/{id}/certificates/ -- TLS certificates, soonest to expire first."""
        return Response(build_certificates(self.get_object()))

    @extend_schema(
        parameters=[OpenApiParameter("days", OpenApiTypes.INT, default=7, description="1 to 90")],
    )
    @action(detail=True, methods=["get"])
    def changes(self, request, pk=None):
        """
        GET /api/organizations/{id}/changes/?days=7
        New hosts, new issues and resolved issues over the last `days`.
        """
        organization = self.get_object()
        return Response(build_changes(organization, self._days(request)))

    @extend_schema(
        parameters=[OpenApiParameter("days", OpenApiTypes.INT, default=7, description="1 to 90")],
        responses={200: OpenApiTypes.BINARY},
    )
    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        """
        GET /api/organizations/{id}/report/?days=7
        A short PDF for someone who will never log in: the grade, what
        changed, and the top risks with what to do about each.
        """
        organization = self.get_object()
        days = self._days(request)
        top_issues = list(
            Finding.objects.counts_toward_risk()
            .filter(asset__organization=organization, asset__is_active=True)
            .select_related("asset")
            .by_severity()[:10]
        )
        summary = build_risk_summary(organization)
        changes = build_changes(organization, days)
        remediation = remediation_metrics(organization)
        narrative = build_narrative(organization, summary, changes, remediation, build_trend(organization, 90))
        content = generate_executive_report(organization, summary, changes, top_issues, narrative, remediation)
        record_activity(request.user, organization, ActivityEvent.Verb.REPORT_DOWNLOADED, "Downloaded the PDF report")
        response = HttpResponse(content, content_type="application/pdf")
        filename = f"{organization.root_domain}-report-{timezone.now().strftime('%Y%m%d')}.pdf"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @staticmethod
    def _days(request) -> int:
        try:
            return min(90, max(1, int(request.query_params.get("days", 7))))
        except ValueError:
            return 7


class AssetFilter(django_filters.FilterSet):
    # tag=payments -> assets carrying that label
    tag = django_filters.CharFilter(method="filter_tag")

    class Meta:
        model = Asset
        fields = ["organization", "asset_type", "is_active", "source", "criticality"]

    def filter_tag(self, queryset, name, value):
        return queryset.filter(tags__contains=[value.strip().lower()])


class AssetViewSet(
    OrgScopedQuerysetMixin, mixins.CreateModelMixin, mixins.UpdateModelMixin, viewsets.ReadOnlyModelViewSet
):
    queryset = (
        Asset.objects.select_related("organization")
        .prefetch_related("technologies")
        .with_scoring_findings()
    )
    serializer_class = AssetSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_class = AssetFilter
    search_fields = ["value"]
    org_field = "organization"
    http_method_names = ["get", "post", "patch", "head", "options"]

    def get_serializer_class(self):
        if self.action == "create":
            return AssetCreateSerializer
        if self.action == "partial_update":
            return AssetUpdateSerializer
        return AssetSerializer

    @extend_schema(request=AssetUpdateSerializer, responses={200: AssetSerializer})
    def partial_update(self, request, *args, **kwargs):
        """
        PATCH /api/assets/{id}/  {"criticality": "crown_jewel", "tags": ["payments"]}
        Business context for a host. Analyst or higher.
        """
        asset = self.get_object()
        require_org_role(request.user, asset.organization, Membership.Role.ANALYST)
        serializer = AssetUpdateSerializer(asset, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        changes = []
        if "criticality" in serializer.validated_data:
            changes.append(f"importance {asset.get_criticality_display().lower()}")
        if "tags" in serializer.validated_data:
            changes.append("labels " + (", ".join(asset.tags) or "none"))
        record_activity(
            request.user, asset.organization, ActivityEvent.Verb.ASSET_UPDATED,
            f"Set {asset.value}'s " + " and ".join(changes),
        )
        return Response(AssetSerializer(self.get_queryset().get(id=asset.id)).data)

    @extend_schema(request=AssetBulkCreateSerializer, responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["post"])
    def bulk(self, request):
        """
        POST /api/assets/bulk/  {"organization": "<uuid>", "values": ["vpn.example.com", ...]}
        Adds many hosts at once (pasted from a spreadsheet or a CMDB
        export). Same rules as adding one; each value that can't be added
        is listed with the reason, and the rest are added. Analyst or higher.
        """
        serializer = AssetBulkCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organization = serializer.validated_data["organization"]
        if not user_can_access_org(request.user, organization):
            raise PermissionDenied("You are not a member of this organization.")
        require_org_role(request.user, organization, Membership.Role.ANALYST)

        added, skipped = [], []
        for raw in serializer.validated_data["values"]:
            value = raw.strip()
            if not value or value in added:
                continue
            one = AssetCreateSerializer(data={"organization": organization.id, "value": value})
            if one.is_valid():
                added.append(one.save().value)
            else:
                reason = one.errors.get("value") or one.errors.get("non_field_errors") or ["Not valid."]
                skipped.append({"value": value, "reason": str(reason[0])})
        if added:
            record_activity(
                request.user, organization, ActivityEvent.Verb.ASSET_ADDED,
                f"Imported {len(added)} host(s), starting with {added[0]}",
            )
        return Response({"added": added, "skipped": skipped})

    @extend_schema(request=AssetCreateSerializer, responses={201: AssetSerializer})
    def create(self, request, *args, **kwargs):
        """
        POST /api/assets/  {"organization": "<uuid>", "value": "vpn.example.com"}
        Adds a host that discovery hasn't found. Analyst or higher. It
        must be the organization's root domain or a name under it, so
        manual assets stay inside the domain the organization proved it owns.
        """
        serializer = AssetCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organization = serializer.validated_data["organization"]
        if not user_can_access_org(request.user, organization):
            raise PermissionDenied("You are not a member of this organization.")
        require_org_role(request.user, organization, Membership.Role.ANALYST)
        asset = serializer.save()
        record_activity(request.user, organization, ActivityEvent.Verb.ASSET_ADDED, f"Added {asset.value} manually")
        asset = self.get_queryset().get(id=asset.id)
        return Response(AssetSerializer(asset).data, status=status.HTTP_201_CREATED)


class ScanJobViewSet(OrgScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = ScanJob.objects.select_related("organization", "asset", "triggered_by")
    serializer_class = ScanJobSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["organization", "asset", "scanner_name", "status", "trigger", "run_id"]
    org_field = "organization"

    @extend_schema(
        parameters=[
            OpenApiParameter("organization", OpenApiTypes.UUID, required=True),
            OpenApiParameter("trigger", OpenApiTypes.STR, enum=ScanJob.Trigger.values),
            OpenApiParameter("status", OpenApiTypes.STR, enum=["running", "failed", "success"]),
        ],
        responses={200: OpenApiTypes.OBJECT},
    )
    @action(detail=False, methods=["get"], filter_backends=[])
    def runs(self, request):
        """
        GET /api/scan-jobs/runs/?organization=<uuid>
        Scan history grouped by where it came from: one row per run (a night's
        schedule, a Run scan click, a host re-check, a single scan), with what
        it covered, how far it has got and what it found. Newest first.
        Filters: trigger, status (running: not finished yet; failed: had failures).
        """
        params = request.query_params
        organization = params.get("organization")
        if not organization:
            raise ValidationError({"organization": ["Choose one of your organizations."]})
        jobs = super().get_queryset().filter(organization_id=organization)
        if params.get("trigger") in ScanJob.Trigger.values:
            jobs = jobs.filter(trigger=params["trigger"])
        unfinished = [ScanJob.Status.PENDING, ScanJob.Status.RUNNING, ScanJob.Status.RETRYING]
        runs = (
            jobs.order_by().values("run_id", "trigger", "triggered_by")
            .annotate(
                jobs=Count("id"),
                succeeded=Count("id", filter=Q(status=ScanJob.Status.SUCCESS)),
                failed=Count("id", filter=Q(status=ScanJob.Status.FAILED)),
                unfinished=Count("id", filter=Q(status__in=unfinished)),
                scanners=Count("scanner_name", distinct=True),
                hosts=Count("asset", distinct=True),
                organization_level=Count("id", filter=Q(asset__isnull=True)),
                first_scanner=Min("scanner_name"), last_scanner=Max("scanner_name"),
                first_asset=Min("asset__value"), last_asset=Max("asset__value"),
                started=Min("created_at"), finished=Max("finished_at"),
            )
        )
        if params.get("status") == "running":
            runs = runs.filter(unfinished__gt=0)
        elif params.get("status") == "failed":
            runs = runs.filter(failed__gt=0)
        runs = runs.order_by("-started")

        paginator = self.paginator
        page = paginator.paginate_queryset(runs, request, view=self)
        users = {u.id: u for u in User.objects.filter(id__in={r["triggered_by"] for r in page if r["triggered_by"]})}
        labels = {name: get_scanner(name).label or name for name in list_scanners()}
        new_findings = dict(
            Finding.objects.filter(scan_job__run_id__in=[r["run_id"] for r in page])
            .values_list("scan_job__run_id").annotate(n=Count("id", filter=Q(first_seen__gte=F("scan_job__created_at"))))
        )
        results = []
        for run in page:
            one_scanner = run["first_scanner"] == run["last_scanner"]
            one_host = run["hosts"] <= 1 and not (run["hosts"] and run["organization_level"])
            host = run["first_asset"] if run["hosts"] == 1 and run["first_asset"] == run["last_asset"] else None
            results.append({
                "run_id": run["run_id"],
                "trigger": run["trigger"],
                "trigger_label": ScanJob.Trigger(run["trigger"]).label,
                "triggered_by": person(users.get(run["triggered_by"])),
                "scanner_name": run["first_scanner"] if one_scanner else None,
                "scanner_label": labels.get(run["first_scanner"], run["first_scanner"]) if one_scanner else None,
                "scanners": run["scanners"],
                "hosts": run["hosts"],
                "host": host if one_host else None,
                "organization_level": run["organization_level"] > 0,
                "jobs": run["jobs"],
                "succeeded": run["succeeded"],
                "failed": run["failed"],
                "unfinished": run["unfinished"],
                "new_findings": new_findings.get(run["run_id"], 0),
                "started": run["started"],
                "finished": run["finished"] if not run["unfinished"] else None,
            })
        return paginator.get_paginated_response(results)

    @action(detail=False, methods=["post"])
    def trigger(self, request):
        """
        POST /api/scan-jobs/trigger/
        Body: {"scanner_name": "nmap", "organization_id": "<uuid>"}   -- whole domain
             or {"scanner_name": "nmap", "asset_id": "<uuid>"}          -- one asset

        With organization_id the scanner runs for the whole domain:
        once for an organization-level scanner, or once per active
        asset for an asset-level one. Responds 202 with a batch id;
        follow it with GET /api/scan-jobs/progress/. Refused with 409
        while that scanner's previous domain-wide run is unfinished.

        With asset_id it creates one ScanJob (idempotent --
        retriggering the same scanner against the same asset on the
        same day returns the existing job unless `force` is set).

        Explicitly checks org membership here (rather than relying only
        on queryset scoping, since this is a write action creating a
        NEW row, not reading an existing one) -- without this check a
        member of Org A could trigger scans against Org B's assets just
        by guessing/enumerating a UUID.
        """
        serializer = ScanJobTriggerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if not user_can_access_org(request.user, data["organization"]):
            raise PermissionDenied("You are not a member of this organization.")
        require_org_role(request.user, data["organization"], Membership.Role.ANALYST)

        if not data["organization"].scans_allowed:
            raise PermissionDenied(
                "Scanning is disabled for this organization until its domain is verified "
                "and the organization is active."
            )

        if data["asset"] is None:
            return self._start_domain_scan(data["organization"], data["scanner_name"])

        # A re-check groups under the run id it was given, unless that id is already
        # someone else's run (or another organization's): then it gets its own.
        run_id = data.get("run_id") or uuid.uuid4()
        if ScanJob.objects.filter(run_id=run_id).exclude(
            organization=data["organization"], triggered_by=request.user, trigger=ScanJob.Trigger.RECHECK
        ).exists():
            run_id = uuid.uuid4()

        target_value = data["asset"].value
        if data["organization"].is_out_of_scope(target_value):
            return Response(
                {"detail": f"{target_value} is on this organization's never-scan list."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if data["force"]:
            # Unique nonce guarantees a brand-new ScanJob every time,
            # bypassing same-day idempotency entirely -- this is what a
            # manual "scan again" button should call.
            idempotency_key = ScanJob.build_idempotency_key(
                data["scanner_name"], target_value, nonce=uuid.uuid4().hex
            )
        else:
            idempotency_key = ScanJob.build_idempotency_key(data["scanner_name"], target_value)

        scan_job, created = ScanJob.objects.get_or_create(
            idempotency_key=idempotency_key,
            defaults=dict(
                organization=data["organization"],
                asset=data["asset"],
                scanner_name=data["scanner_name"],
                trigger=ScanJob.Trigger.RECHECK if data["reason"] == "recheck" else ScanJob.Trigger.SINGLE,
                triggered_by=request.user,
                run_id=run_id,
            ),
        )

        if created or scan_job.status == ScanJob.Status.FAILED:
            run_scan_job.delay(str(scan_job.id))
            record_activity(
                request.user, data["organization"], ActivityEvent.Verb.SCAN_STARTED,
                f"Started {get_scanner(data['scanner_name']).label or data['scanner_name']} on {target_value}",
            )

        return Response(
            ScanJobSerializer(scan_job).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    UNFINISHED = [ScanJob.Status.PENDING, ScanJob.Status.RUNNING, ScanJob.Status.RETRYING]

    def _start_domain_scan(self, organization, scanner_name):
        already_running = Response(
            {"detail": "This scanner is still running for this organization. Wait for it to finish."},
            status=status.HTTP_409_CONFLICT,
        )
        in_progress = ScanJob.objects.filter(
            organization=organization,
            scanner_name=scanner_name,
            batch_id__isnull=False,
            status__in=self.UNFINISHED,
            created_at__gte=timezone.now() - timedelta(days=1),
        ).exists()
        if in_progress:
            return already_running

        # Covers the gap between this request and the fan-out task
        # writing its first job, when the query above still sees nothing.
        batch_id = uuid.uuid4()
        lock_key = domain_scan_lock_key(organization.id, scanner_name)
        if not cache.add(lock_key, str(batch_id), timeout=15 * 60):
            return already_running

        if get_scanner(scanner_name).applies_to == "organization":
            scan_job = ScanJob.objects.create(
                organization=organization,
                asset=None,
                scanner_name=scanner_name,
                batch_id=batch_id,
                trigger=ScanJob.Trigger.DOMAIN,
                run_id=batch_id,
                triggered_by=self.request.user,
                idempotency_key=ScanJob.build_idempotency_key(
                    scanner_name, organization.root_domain, nonce=str(batch_id)
                ),
            )
            run_scan_job.delay(str(scan_job.id))
            cache.delete(lock_key)
            target_count = 1
        else:
            target_count = organization.scannable_assets().count()
            fan_out_domain_scan.delay(str(organization.id), scanner_name, str(batch_id), self.request.user.id)

        scanner = get_scanner(scanner_name)
        record_activity(
            self.request.user, organization, ActivityEvent.Verb.SCAN_STARTED,
            f"Started {scanner.label or scanner_name} on "
            + (organization.root_domain if target_count == 1 else f"all {target_count:,} assets"),
        )
        return Response(
            DomainScanStartedSerializer(
                {"batch_id": batch_id, "scanner_name": scanner_name, "target_count": target_count}
            ).data,
            status=status.HTTP_202_ACCEPTED,
        )

    @extend_schema(
        parameters=[OpenApiParameter("organization", OpenApiTypes.UUID, required=True)],
        responses={200: ScanProgressSerializer(many=True)},
    )
    @action(detail=False, methods=["get"], pagination_class=None, filter_backends=[])
    def progress(self, request):
        """
        GET /api/scan-jobs/progress/?organization=<uuid>
        For each scanner, where its most recent domain-wide run stands:
        how many of its scans are waiting, running, done and failed.
        One entry per scanner that has had such a run in the last 30 days.
        """
        organization_id = request.query_params.get("organization")
        try:
            uuid.UUID(str(organization_id))
        except ValueError:
            return Response(
                {"organization": ["A valid organization id is required."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        jobs = self.get_queryset().order_by().filter(
            organization_id=organization_id,
            batch_id__isnull=False,
            created_at__gte=timezone.now() - timedelta(days=30),
        )

        latest: dict[str, dict] = {}
        for row in jobs.values("scanner_name", "batch_id").annotate(started_at=Min("created_at")):
            current = latest.get(row["scanner_name"])
            if current is None or row["started_at"] > current["started_at"]:
                latest[row["scanner_name"]] = row

        counts: dict = {}
        by_status = (
            jobs.filter(batch_id__in=[row["batch_id"] for row in latest.values()])
            .values("batch_id", "status")
            .annotate(count=Count("id"))
        )
        for row in by_status:
            counts.setdefault(row["batch_id"], {})[row["status"]] = row["count"]

        result = []
        for scanner_name, row in sorted(latest.items()):
            status_counts = counts.get(row["batch_id"], {})
            pending = status_counts.get(ScanJob.Status.PENDING, 0)
            running = status_counts.get(ScanJob.Status.RUNNING, 0) + status_counts.get(
                ScanJob.Status.RETRYING, 0
            )
            success = status_counts.get(ScanJob.Status.SUCCESS, 0)
            failed = status_counts.get(ScanJob.Status.FAILED, 0)
            result.append({
                "scanner_name": scanner_name,
                "batch_id": row["batch_id"],
                "started_at": row["started_at"],
                "total": pending + running + success + failed,
                "pending": pending,
                "running": running,
                "success": success,
                "failed": failed,
                "finished": pending + running == 0,
            })
        return Response(ScanProgressSerializer(result, many=True).data)


class FindingViewSet(OrgScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.select_related(
        "asset__organization", "status_changed_by", "assignee"
    ).by_severity()
    serializer_class = FindingSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_class = FindingFilter
    search_fields = ["title", "asset__value"]
    org_field = "asset__organization"

    @extend_schema(request=FindingTriageSerializer, responses={200: FindingSerializer})
    @action(detail=True, methods=["post"])
    def triage(self, request, pk=None):
        """
        POST /api/findings/{id}/triage/
        Body: {"status": "open" | "accepted" | "false_positive", "note": "..."}

        Records an analyst's verdict. Accepted and false-positive
        findings stop counting toward risk scores; the verdict survives
        re-scans. Needs the Analyst role or higher.
        """
        finding = self.get_object()
        require_org_role(request.user, finding.asset.organization, Membership.Role.ANALYST)

        serializer = FindingTriageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        self._apply_triage(finding, serializer.validated_data)
        return Response(FindingSerializer(finding).data)

    def _apply_triage(self, finding, data):
        finding.status = data["status"]
        finding.status_note = data["note"]
        finding.status_changed_at = timezone.now()
        finding.status_changed_by = self.request.user
        finding.accepted_until = data.get("accepted_until") if data["status"] == Finding.Status.ACCEPTED else None
        # update_fields keeps last_seen (auto_now) meaning "last seen by
        # a scanner" -- triaging a finding isn't a sighting.
        finding.save(
            update_fields=["status", "status_note", "status_changed_at", "status_changed_by", "accepted_until"]
        )
        verdict = finding.get_status_display().lower()
        if finding.accepted_until:
            verdict += f" until {finding.accepted_until.isoformat()}"
        record_activity(
            self.request.user, finding.asset.organization, ActivityEvent.Verb.FINDING_TRIAGED,
            f"Marked '{finding.title}' on {finding.asset.value} as {verdict}",
            finding=finding,
        )

    @extend_schema(request=FindingAssignSerializer, responses={200: FindingSerializer})
    @action(detail=True, methods=["post"])
    def assign(self, request, pk=None):
        """
        POST /api/findings/{id}/assign/  {"assignee": <user id> | null}
        Makes someone responsible for fixing the finding (or nobody).
        Analyst or higher; the assignee must be a member of the organization.
        """
        finding = self.get_object()
        organization = finding.asset.organization
        require_org_role(request.user, organization, Membership.Role.ANALYST)

        serializer = FindingAssignSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        assignee_id = serializer.validated_data["assignee"]
        assignee = None
        if assignee_id is not None:
            membership = organization.memberships.select_related("user").filter(user_id=assignee_id).first()
            if membership is None:
                return Response(
                    {"assignee": ["That person is not a member of this organization."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            assignee = membership.user

        self._apply_assignee(finding, assignee)
        return Response(FindingSerializer(finding).data)

    def _apply_assignee(self, finding, assignee):
        finding.assignee = assignee
        finding.save(update_fields=["assignee"])
        record_activity(
            self.request.user, finding.asset.organization, ActivityEvent.Verb.FINDING_ASSIGNED,
            f"Assigned '{finding.title}' on {finding.asset.value} to {assignee.username}"
            if assignee else f"Unassigned '{finding.title}' on {finding.asset.value}",
            finding=finding,
        )

    @extend_schema(request=FindingBulkSerializer, responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["post"])
    def bulk(self, request):
        """
        POST /api/findings/bulk/
        {"ids": [...], "action": "triage", "status": "accepted", "note": "...", "accepted_until": "2027-01-31"}
        {"ids": [...], "action": "assign", "assignee": <user id> | null}

        The same triage or assignment for many findings at once. They
        must all belong to one organization, where the caller is an
        Analyst or higher.
        """
        serializer = FindingBulkSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        findings = list(self.get_queryset().filter(id__in=data["ids"]))
        if len(findings) != len(set(data["ids"])):
            return Response(
                {"ids": ["Some of these findings don't exist or aren't yours to see."]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        organizations = {finding.asset.organization for finding in findings}
        if len(organizations) != 1:
            return Response(
                {"ids": ["Choose findings from one organization at a time."]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        organization = organizations.pop()
        require_org_role(request.user, organization, Membership.Role.ANALYST)

        if data["action"] == "assign":
            assignee = None
            if data["assignee"] is not None:
                membership = organization.memberships.select_related("user").filter(user_id=data["assignee"]).first()
                if membership is None:
                    return Response(
                        {"assignee": ["That person is not a member of this organization."]},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                assignee = membership.user
            for finding in findings:
                self._apply_assignee(finding, assignee)
        else:
            for finding in findings:
                self._apply_triage(finding, data)
        return Response({"updated": len(findings)})

    @extend_schema(methods=["get"], responses={200: FindingCommentSerializer(many=True)})
    @extend_schema(methods=["post"], request=FindingCommentSerializer, responses={201: FindingCommentSerializer})
    @action(detail=True, methods=["get", "post"], pagination_class=None)
    def comments(self, request, pk=None):
        """
        GET  /api/findings/{id}/comments/  -- the discussion, oldest first
        POST /api/findings/{id}/comments/  {"body": "Fixed in tonight's deploy"}
        Any member can read and write: the person fixing it is often a
        developer with the Viewer role.
        """
        finding = self.get_object()
        if request.method == "GET":
            return Response(FindingCommentSerializer(finding.comments.all(), many=True).data)

        serializer = FindingCommentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        comment = serializer.save(finding=finding, author=request.user, author_name=request.user.username)
        record_activity(
            request.user, finding.asset.organization, ActivityEvent.Verb.FINDING_COMMENTED,
            f"Commented on '{finding.title}' on {finding.asset.value}",
            finding=finding,
        )
        return Response(FindingCommentSerializer(comment).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"], pagination_class=None)
    def timeline(self, request, pk=None):
        """
        GET /api/findings/{id}/timeline/
        Everything that happened to this finding, oldest first: when it
        was detected, every triage, assignment and comment, whether it
        came back after a fix, and when it was last seen or resolved.
        """
        finding = self.get_object()
        scanner = finding.scan_job.scanner_name if finding.scan_job_id else ""
        try:
            scanner = get_scanner(scanner).label or scanner
        except ValueError:
            pass
        entries = [{
            "kind": "detected", "at": finding.first_seen, "actor": "",
            "text": f"First detected{' by ' + scanner if scanner else ''}",
        }]
        # Comments are listed with their text below, not as "Commented on...".
        for event in finding.activity.exclude(verb=ActivityEvent.Verb.FINDING_COMMENTED).order_by("created_at"):
            entries.append({
                "kind": event.verb, "at": event.created_at, "actor": event.actor_name, "text": event.summary,
            })
        for comment in finding.comments.all():
            entries.append({
                "kind": "comment", "at": comment.created_at, "actor": comment.author_name, "text": comment.body,
            })
        if finding.is_active:
            # Only worth a line once a later scan has confirmed it again.
            if finding.last_seen - finding.first_seen > timedelta(minutes=1):
                entries.append({
                    "kind": "seen", "at": finding.last_seen, "actor": "", "text": "Last confirmed by a scan",
                })
        elif finding.resolved_at:
            entries.append({
                "kind": "resolved", "at": finding.resolved_at, "actor": "", "text": "No longer detected: fixed",
            })
        entries.sort(key=lambda entry: entry["at"])
        return Response(entries)

    @extend_schema(responses={200: OpenApiTypes.BINARY})
    @action(detail=True, methods=["get"])
    def screenshot(self, request, pk=None):
        """
        GET /api/findings/{id}/screenshot/
        Streams the PNG a screenshot finding points at. Screenshots are
        tenant data like any other finding, so they're served here,
        behind the same auth and org-scoping (get_object() 404s for
        another org's finding), rather than from a public /media/ URL.
        """
        finding = self.get_object()
        if finding.finding_type != Finding.FindingType.SCREENSHOT:
            raise Http404
        # raw_data is scanner-written, but never trust a stored path to stay
        # inside screenshots/ (screenshot_store refuses anything else). The
        # file may be on disk or in object storage (R2/S3).
        image = screenshot_store.open_image(finding.raw_data.get("screenshot_path"))
        if image is None:
            raise Http404

        response = FileResponse(image, content_type="image/png")
        response["Cache-Control"] = "private, max-age=300"
        return response


class ScannerListView(APIView):
    """
    GET /api/scanners/
    Lists every registered scanner plugin -- backs the frontend's
    "Scanners" tab. Reads directly from the plugin registry, so a new
    scanner shows up here automatically with zero changes to this view.

    Not org-scoped -- this describes the PLATFORM's capabilities
    (which scanners exist at all), not any tenant's data.
    """
    @extend_schema(responses={200: ScannerInfoSerializer(many=True)})
    def get(self, request):
        scanners = [
            {
                "name": scanner.name,
                "label": scanner.label or scanner.name,
                "description": scanner.description,
                "category": scanner.category,
                "applies_to": scanner.applies_to,
                "owned_finding_types": scanner.owned_finding_types,
            }
            for scanner in map(get_scanner, list_scanners())
        ]
        serializer = ScannerInfoSerializer(scanners, many=True)
        return Response(serializer.data)


class NotificationRuleViewSet(OrgScopedQuerysetMixin, viewsets.ModelViewSet):
    """
    Full CRUD (unlike the mostly-read-only viewsets above) -- these are
    genuinely user-configured settings, not scanner-populated data.
    """

    queryset = NotificationRule.objects.select_related("organization")
    serializer_class = NotificationRuleSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["organization", "is_active", "min_severity"]
    org_field = "organization"

    def perform_create(self, serializer):
        organization = serializer.validated_data["organization"]
        if not user_can_access_org(self.request.user, organization):
            raise PermissionDenied("You are not a member of this organization.")
        require_org_role(self.request.user, organization, Membership.Role.ADMIN)
        rule = serializer.save()
        record_activity(
            self.request.user, organization, ActivityEvent.Verb.RULE_CREATED,
            f"Added a {rule.get_channel_display().lower()} rule for {rule.destination}",
        )

    def perform_update(self, serializer):
        # The serializer already refuses to change `organization`, so
        # the instance's current org is the only one that matters here.
        require_org_role(self.request.user, serializer.instance.organization, Membership.Role.ADMIN)
        serializer.save()

    def perform_destroy(self, instance):
        require_org_role(self.request.user, instance.organization, Membership.Role.ADMIN)
        record_activity(
            self.request.user, instance.organization, ActivityEvent.Verb.RULE_DELETED,
            f"Deleted the {instance.get_channel_display().lower()} rule for {instance.destination}",
        )
        instance.delete()

    @extend_schema(request=None, responses={200: OpenApiTypes.OBJECT})
    @action(detail=True, methods=["post"], url_path="send-report")
    def send_report(self, request, pk=None):
        """
        POST /api/notification-rules/{id}/send-report/
        Emails the weekly report to this rule's address now, rather than
        waiting for Monday. Admin or higher; email rules only.
        """
        rule = self.get_object()
        require_org_role(request.user, rule.organization, Membership.Role.ADMIN)
        if rule.channel != NotificationRule.Channel.EMAIL:
            return Response(
                {"detail": "Reports can only be emailed; this is a webhook rule."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        send_weekly_report.delay(str(rule.organization_id), [rule.recipient_email])
        return Response({"detail": f"The report is on its way to {rule.recipient_email}."})

    @extend_schema(request=None, responses={200: OpenApiTypes.OBJECT})
    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        """
        POST /api/notification-rules/{id}/test/
        Sends a test alert to the rule's address or channel now, so the
        person setting it up can see it arrive. Admin or higher.
        Answers {"delivered": bool, "detail": "what to tell them"}.
        """
        rule = self.get_object()
        require_org_role(request.user, rule.organization, Membership.Role.ADMIN)
        delivered, detail = send_test_alert(rule)
        return Response({"delivered": delivered, "detail": detail})
