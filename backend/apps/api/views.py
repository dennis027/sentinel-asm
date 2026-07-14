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


class OrganizationViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["name", "root_domain"]


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
