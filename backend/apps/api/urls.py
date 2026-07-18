from rest_framework.routers import DefaultRouter

from .views import (
    AssetViewSet,
    FindingViewSet,
    OrganizationViewSet,
    ScanJobViewSet,
    NotificationRuleViewSet
)

router = DefaultRouter()
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("assets", AssetViewSet, basename="asset")
router.register("scan-jobs", ScanJobViewSet, basename="scanjob")
router.register("findings", FindingViewSet, basename="finding")
router.register("notification-rules", NotificationRuleViewSet, basename="notificationrule")

urlpatterns = router.urls