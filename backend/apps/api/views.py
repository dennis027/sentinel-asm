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

from django.db.models import Count
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.assets.models import Asset
from apps.assets.serializers import AssetSerializer
from apps.findings.models import Finding
from apps.findings.risk_scoring import grade_for_score
from apps.findings.serializers import FindingSerializer
from apps.notifications.models import NotificationRule
from apps.notifications.serializers import NotificationRuleSerializer
from apps.organizations.models import Membership, Organization
from apps.organizations.serializers import OrganizationSerializer
from apps.scanning.models import ScanJob
from apps.scanning.plugins.registry import get_scanner, list_scanners
from apps.scanning.serializers import ScannerInfoSerializer, ScanJobSerializer, ScanJobTriggerSerializer
from apps.scanning.tasks import run_scan_job

from .permissions import OrgScopedQuerysetMixin, user_can_access_org


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

    @action(detail=True, methods=["get"], url_path="risk-summary")
    def risk_summary(self, request, pk=None):
        """
        GET /api/organizations/{id}/risk-summary/
        Aggregates risk across every asset in the org -- average score,
        grade distribution, and active-finding counts by severity.
        Computed on request (same as per-asset risk_score), not stored.
        """
        organization = self.get_object()  # already org-scoped -- 404s if not a member
        assets = list(organization.assets.filter(is_active=True))

        grade_counts: dict[str, int] = {}
        scores = []
        for asset in assets:
            scores.append(asset.risk_score)
            grade_counts[asset.risk_grade] = grade_counts.get(asset.risk_grade, 0) + 1

        average_score = round(sum(scores) / len(scores), 1) if scores else None

        severity_counts = dict(
            Finding.objects.filter(asset__organization=organization, is_active=True)
            .values_list("severity")
            .annotate(count=Count("id"))
        )

        return Response({
            "organization": organization.name,
            "asset_count": len(assets),
            "average_risk_score": average_score,
            "average_risk_grade": grade_for_score(round(average_score)) if average_score is not None else None,
            "grade_distribution": grade_counts,
            "active_findings_by_severity": {
                severity: severity_counts.get(severity, 0)
                for severity in Finding.Severity.values
            },
        })


class AssetViewSet(OrgScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Asset.objects.select_related("organization").prefetch_related("technologies")
    serializer_class = AssetSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["organization", "asset_type", "is_active"]
    search_fields = ["value"]
    org_field = "organization"


class ScanJobViewSet(OrgScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = ScanJob.objects.select_related("organization", "asset")
    serializer_class = ScanJobSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["organization", "asset", "scanner_name", "status"]
    org_field = "organization"

    @action(detail=False, methods=["post"])
    def trigger(self, request):
        """
        POST /api/scan-jobs/trigger/
        Body: {"scanner_name": "nmap", "asset_id": "<uuid>"}
             or {"scanner_name": "subfinder", "organization_id": "<uuid>"}

        Creates a ScanJob (idempotent -- retriggering the same scanner
        against the same target on the same day returns the existing
        job instead of duplicating it) and enqueues it on Celery.

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

        target_value = data["asset"].value if data["asset"] else data["organization"].root_domain

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
            ),
        )

        if created or scan_job.status == ScanJob.Status.FAILED:
            run_scan_job.delay(str(scan_job.id))

        return Response(
            ScanJobSerializer(scan_job).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class FindingViewSet(OrgScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.select_related("asset")
    serializer_class = FindingSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["asset", "finding_type", "severity", "is_active"]
    search_fields = ["title"]
    org_field = "asset__organization"


class ScannerListView(APIView):
    """
    GET /api/scanners/
    Lists every registered scanner plugin -- backs the frontend's
    "Scanners" tab. Reads directly from the plugin registry, so a new
    scanner shows up here automatically with zero changes to this view.

    Not org-scoped -- this describes the PLATFORM's capabilities
    (which scanners exist at all), not any tenant's data.
    """

    def get(self, request):
        scanners = [
            {
                "name": name,
                "applies_to": get_scanner(name).applies_to,
                "owned_finding_types": get_scanner(name).owned_finding_types,
            }
            for name in list_scanners()
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
        serializer.save()