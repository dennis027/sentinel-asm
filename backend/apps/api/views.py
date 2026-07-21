"""
Thin, mostly-read viewsets over the core models. The only real write
action is `trigger` on ScanJobViewSet -- everything else (Organization,
Asset, Finding) is populated by scanners, not by API clients.
"""

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.assets.models import Asset
from apps.assets.serializers import AssetSerializer
from apps.findings.models import Finding
from apps.findings.serializers import FindingSerializer
from apps.organizations.models import Organization
from apps.organizations.serializers import OrganizationSerializer
from apps.scanning.models import ScanJob
from apps.scanning.serializers import ScanJobSerializer, ScanJobTriggerSerializer
from apps.scanning.tasks import run_scan_job
from apps.notifications.models import NotificationRule
from apps.notifications.serializers import NotificationRuleSerializer
from django.db.models import Count
from apps.findings.risk_scoring import grade_for_score


class OrganizationViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["name", "root_domain"]

    @action(detail=True, methods=["get"], url_path="risk-summary")
    def risk_summary(self, request, pk=None):
        """
        GET /api/organizations/{id}/risk-summary/
        Aggregates risk across every asset in the org -- average score,
        grade distribution, and active-finding counts by severity.
        Computed on request (same as per-asset risk_score), not stored.
        """
        organization = self.get_object()
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


class AssetViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Asset.objects.select_related("organization").prefetch_related("technologies")
    serializer_class = AssetSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["organization", "asset_type", "is_active"]
    search_fields = ["value"]


class ScanJobViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanJob.objects.select_related("organization", "asset")
    serializer_class = ScanJobSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["organization", "asset", "scanner_name", "status"]

    @action(detail=False, methods=["post"])
    def trigger(self, request):
        """
        POST /api/scan-jobs/trigger/
        Body: {"scanner_name": "nmap", "asset_id": "<uuid>"}
             or {"scanner_name": "subfinder", "organization_id": "<uuid>"}

        Creates a ScanJob (idempotent -- retriggering the same scanner
        against the same target on the same day returns the existing
        job instead of duplicating it) and enqueues it on Celery.
        """
        serializer = ScanJobTriggerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        idempotency_key = ScanJob.build_idempotency_key(
            data["scanner_name"],
            data["asset"].value if data["asset"] else data["organization"].root_domain,
        )
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


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.select_related("asset")
    serializer_class = FindingSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["asset", "finding_type", "severity", "is_active"]
    search_fields = ["title"]


class NotificationRuleViewSet(viewsets.ModelViewSet):
    """
    Full CRUD (unlike the mostly-read-only viewsets above) -- these are
    genuinely user-configured settings, not scanner-populated data.
    """

    queryset = NotificationRule.objects.select_related("organization")
    serializer_class = NotificationRuleSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["organization", "is_active", "min_severity"]