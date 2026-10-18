from django.urls import path

from apps.logs.views import (
    ErrorGroupViewSet,
    LogAlertRuleViewSet,
    LogDetectionViewSet,
    LogEventViewSet,
    LogOverviewView,
    LogSourceViewSet,
)
from rest_framework.routers import DefaultRouter

from .views import (
    AssetViewSet,
    FindingViewSet,
    OrganizationViewSet,
    ScanJobViewSet,
    NotificationRuleViewSet,
    ScannerListView
)

router = DefaultRouter()
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("assets", AssetViewSet, basename="asset")
router.register("scan-jobs", ScanJobViewSet, basename="scanjob")
router.register("findings", FindingViewSet, basename="finding")
router.register("notification-rules", NotificationRuleViewSet, basename="notificationrule")
router.register("log-sources", LogSourceViewSet, basename="logsource")
router.register("log-events", LogEventViewSet, basename="logevent")
router.register("log-detections", LogDetectionViewSet, basename="logdetection")
router.register("error-groups", ErrorGroupViewSet, basename="errorgroup")
router.register("log-alert-rules", LogAlertRuleViewSet, basename="logalertrule")

urlpatterns = [
    path("scanners/", ScannerListView.as_view(), name="scanner-list"),
    path("logs/overview/", LogOverviewView.as_view(), name="log-overview"),
] + router.urls