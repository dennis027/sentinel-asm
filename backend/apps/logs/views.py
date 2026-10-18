from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

from django.conf import settings
from django.http import FileResponse, Http404
from django.db.models import Case, Count, IntegerField, Max, Min, Q, Value, When
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api.permissions import OrgScopedQuerysetMixin, require_org_role, user_can_access_org
from apps.audit_logs.activity import record as record_activity
from apps.audit_logs.models import ActivityEvent
from apps.organizations.models import Membership, Organization

from .detections import RULES
from .models import ErrorGroup, LogAlertRule, LogDetection, LogEvent, LogSource
from .serializers import (
    ErrorGroupSerializer,
    LogAlertRuleSerializer,
    LogDetectionSerializer,
    LogEventSerializer,
    LogSourceSerializer,
)

# Time ranges the search offers, in hours.
SINCE_CHOICES = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30, "all": None}


def _ingest_url(request) -> str:
    return settings.LOG_INGEST_URL or request.build_absolute_uri("/api/ingest/")


class LogSourceViewSet(
    OrgScopedQuerysetMixin, mixins.CreateModelMixin, mixins.DestroyModelMixin, viewsets.ReadOnlyModelViewSet
):
    """
    The servers sending logs. Anyone in the organization can see them;
    admins connect and disconnect them. Connecting one returns its
    ingest key -- the only time it is ever shown.
    """

    queryset = LogSource.objects.annotate(
        open_detections=Count("detections", filter=Q(detections__status=LogDetection.Status.OPEN))
    )
    serializer_class = LogSourceSerializer
    org_field = "organization"
    pagination_class = None

    def get_queryset(self):
        # super() is the org-scoping mixin: only the caller's organizations.
        queryset = super().get_queryset()
        organization = self.request.query_params.get("organization")
        return queryset.filter(organization_id=organization) if organization else queryset

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organization = serializer.validated_data["organization"]
        if not user_can_access_org(request.user, organization):
            raise PermissionDenied("You are not a member of this organization.")
        require_org_role(request.user, organization, Membership.Role.ADMIN)
        source = LogSource(**serializer.validated_data, created_by=request.user)
        key = source.issue_key()
        source.save()
        record_activity(
            request.user, organization, ActivityEvent.Verb.LOG_SOURCE_ADDED,
            f"Connected {source.name} ({source.get_os_display()}) to server logs",
        )
        data = LogSourceSerializer(source).data
        return Response({**data, "key": key, "ingest_url": _ingest_url(request)}, status=status.HTTP_201_CREATED)

    def perform_destroy(self, instance):
        require_org_role(self.request.user, instance.organization, Membership.Role.ADMIN)
        record_activity(
            self.request.user, instance.organization, ActivityEvent.Verb.LOG_SOURCE_REMOVED,
            f"Disconnected {instance.name}; its logs were deleted",
        )
        instance.delete()

    @extend_schema(request=None, responses={200: OpenApiTypes.OBJECT})
    @action(detail=True, methods=["post"], url_path="replace-key")
    def replace_key(self, request, pk=None):
        """A new ingest key for this server; the old one stops working at once. Admin or higher."""
        source = self.get_object()
        require_org_role(request.user, source.organization, Membership.Role.ADMIN)
        key = source.issue_key()
        source.save(update_fields=["key_prefix", "key_hash"])
        record_activity(
            request.user, source.organization, ActivityEvent.Verb.LOG_KEY_REPLACED,
            f"Replaced the ingest key for {source.name}",
        )
        return Response({**LogSourceSerializer(source).data, "key": key, "ingest_url": _ingest_url(request)})


class LogEventPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200


# Level filter values: one level, or "problems" for warnings and errors together.
LEVEL_FILTERS = {"info": ["info"], "warning": ["warning"], "error": ["error"], "problems": ["warning", "error"]}
# Bucket sizes the timeline can use, in seconds; the smallest that gives at most 60 bars wins.
BUCKETS = [60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 7 * 86400]
EXPORT_LIMIT = 50_000


def filter_events(queryset, params, skip=()):
    """
    The search's filters, shared by the list, the timeline, the counts
    and the export. `skip` leaves some out (the counts for "level" are
    worked out without the level filter, so every option shows its count).
    """
    def wanted(name):
        return params.get(name) and name not in skip

    if params.get("organization"):
        queryset = queryset.filter(organization_id=params["organization"])
    if wanted("source"):
        queryset = queryset.filter(source_id=params["source"])
    if wanted("category"):
        queryset = queryset.filter(category=params["category"])
    if wanted("level") and params["level"] in LEVEL_FILTERS:
        queryset = queryset.filter(level__in=LEVEL_FILTERS[params["level"]])
    if wanted("user"):
        queryset = queryset.filter(user__iexact=params["user"])
    if wanted("ip"):
        queryset = queryset.filter(src_ip=params["ip"])
    if wanted("fingerprint"):
        queryset = queryset.filter(fingerprint=params["fingerprint"])
    if params.get("after_id", "").isdigit():
        # Live updates: only what arrived since the newest event the page already shows.
        queryset = queryset.filter(id__gt=int(params["after_id"]))
    for field in ("service", "release"):
        if wanted(field):
            queryset = queryset.filter(**{field: params[field]})
    if wanted("host"):
        queryset = queryset.filter(host__iexact=params["host"])
    if wanted("status"):
        # "5xx", "4xx" or an exact code
        status_filter = params["status"].lower()
        if status_filter.endswith("xx") and status_filter[0].isdigit():
            base = int(status_filter[0]) * 100
            queryset = queryset.filter(http_status__gte=base, http_status__lt=base + 100)
        elif status_filter.isdigit():
            queryset = queryset.filter(http_status=int(status_filter))
    if wanted("q"):
        q = params["q"].strip()
        queryset = queryset.filter(
            Q(message__icontains=q) | Q(user__icontains=q) | Q(host__icontains=q) | Q(program__icontains=q)
            | Q(service__icontains=q)
        )
    start, end = time_range(params)
    if start:
        queryset = queryset.filter(occurred_at__gte=start)
    if end:
        queryset = queryset.filter(occurred_at__lte=end)
    return queryset


def _when(value):
    from django.utils.dateparse import parse_datetime

    parsed = parse_datetime(value) if value else None
    if value and parsed is None:
        raise ValidationError({"after": ["Use a date and time such as 2026-10-17T09:00:00Z."]})
    if parsed and timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, dt_timezone.utc)
    return parsed


def time_range(params):
    """(start, end) from since=1h/24h/7d/30d/all (default 24h) and/or after/before; either may be None."""
    after, before = _when(params.get("after")), _when(params.get("before"))
    since = params.get("since", "24h")
    hours = SINCE_CHOICES.get(since, 24) if since != "custom" else None
    start = after or (timezone.now() - timedelta(hours=hours) if hours else None)
    return start, before


class LogEventViewSet(OrgScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    """
    GET /api/log-events/?organization=<id>
    Filters: source, category, level (info, warning, error, or problems for
    both), service, release, host, user, ip, status (5xx, 4xx or a code),
    fingerprint, q (searches message, user, host, program and service),
    since (1h, 24h, 7d, 30d, all, or custom with after/before), after, before.
    Also: facets/ (counts for each filter's options), timeline/ (events over
    time) and export/ (CSV), with the same filters.
    """

    queryset = LogEvent.objects.select_related("source")
    serializer_class = LogEventSerializer
    pagination_class = LogEventPagination
    org_field = "organization"

    def get_queryset(self):
        return filter_events(super().get_queryset(), self.request.query_params)

    def _scoped(self):
        # The organization-scoped events before any of the search's filters.
        return super().get_queryset()

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["get"])
    def facets(self, request):
        """
        How many events each option of each filter would give, with the other
        filters applied: {"level": {"error": 12, ...}, "service": [["payments", 40], ...], ...}.
        """
        params = request.query_params
        if not params.get("organization"):
            raise ValidationError({"organization": ["Choose one of your organizations."]})
        base = self._scoped()

        def counts(field, top=None):
            rows = (filter_events(base, params, skip=(field,)).exclude(**{field: ""})
                    .values_list(field).annotate(n=Count("id")).order_by("-n"))
            return list(rows[:top]) if top else dict(rows)

        sources = dict(filter_events(base, params, skip=("source",)).values_list("source_id").annotate(n=Count("id")))
        statuses = filter_events(base, params, skip=("status",)).filter(http_status__isnull=False)
        return Response({
            "source": {str(k): v for k, v in sources.items()},
            "category": counts("category"),
            "level": counts("level"),
            "service": counts("service", 30),
            "release": counts("release", 30),
            "host": counts("host", 30),
            "status": {
                f"{n}xx": statuses.filter(http_status__gte=n * 100, http_status__lt=n * 100 + 100).count()
                for n in (2, 3, 4, 5)
            },
        })

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["get"])
    def timeline(self, request):
        """Matching events over time, in at most 60 bars, split into errors, warnings and the rest."""
        from django.db.models.expressions import RawSQL

        params = request.query_params
        queryset = self.get_queryset()
        start, end = time_range(params)
        end = end or timezone.now()
        if start is None:
            start = queryset.aggregate(first=Min("occurred_at"))["first"] or end - timedelta(hours=24)
        span = max((end - start).total_seconds(), 60)
        # 61: "the last hour" is a moment over 3600 seconds by the time it is measured.
        size = next((b for b in BUCKETS if span / b <= 61), BUCKETS[-1])
        rows = (
            queryset.order_by()
            .annotate(bucket=RawSQL("floor(extract(epoch from logs_logevent.occurred_at) / %s)", (size,)))
            .values("bucket", "level").annotate(n=Count("id"))
        )
        bars: dict = {}
        for row in rows:
            bar = bars.setdefault(int(row["bucket"]), {"error": 0, "warning": 0, "info": 0})
            bar[row["level"] if row["level"] in bar else "info"] += row["n"]
        first = int(start.timestamp() // size)
        last = int(end.timestamp() // size)
        return Response({
            "start": start, "end": end, "bucket_seconds": size,
            "buckets": [
                {"t": datetime.fromtimestamp(i * size, tz=dt_timezone.utc), **bars.get(i, {"error": 0, "warning": 0, "info": 0})}
                for i in range(first, last + 1)
            ],
        })

    @extend_schema(responses={(200, "text/csv"): OpenApiTypes.STR})
    @action(detail=False, methods=["get"])
    def export(self, request):
        """The matching events as CSV (newest first, at most 50,000)."""
        import csv

        from django.http import StreamingHttpResponse

        queryset = self.get_queryset().order_by("-occurred_at", "-id")[:EXPORT_LIMIT]
        columns = ["occurred_at", "source", "host", "service", "release", "level", "category", "action", "user",
                   "src_ip", "http_status", "message"]

        class Echo:
            def write(self, value):
                return value

        writer = csv.writer(Echo())

        def rows():
            yield writer.writerow(columns)
            for event in queryset.iterator(chunk_size=2000):
                yield writer.writerow([
                    event.occurred_at.isoformat(), event.source.name, event.host, event.service, event.release,
                    event.level, event.category, event.action, event.user, event.src_ip or "",
                    event.http_status or "",
                    # Spreadsheet formula injection: a cell starting with = + - @ is shown as text.
                    ("'" + event.message) if event.message[:1] in ("=", "+", "-", "@") else event.message,
                ])

        response = StreamingHttpResponse(rows(), content_type="text/csv")
        response["Content-Disposition"] = (
            f'attachment; filename="densight-logs-{timezone.now().strftime("%Y%m%d-%H%M")}.csv"'
        )
        return response


class LogDetectionViewSet(OrgScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    """GET /api/log-detections/?organization=<id>&status=open -- what the detections found."""

    queryset = LogDetection.objects.select_related("source", "resolved_by")
    serializer_class = LogDetectionSerializer
    org_field = "organization"

    def get_queryset(self):
        params = self.request.query_params
        queryset = super().get_queryset()
        for field in ("organization", "source"):
            if params.get(field):
                queryset = queryset.filter(**{f"{field}_id": params[field]})
        for field in ("status", "severity"):
            if params.get(field):
                queryset = queryset.filter(**{field: params[field]})
        if params.get("rule") == "custom":
            queryset = queryset.filter(rule__startswith="custom:")
        elif params.get("rule"):
            queryset = queryset.filter(rule=params["rule"])
        if params.get("q"):
            q = params["q"].strip()
            queryset = queryset.filter(Q(title__icontains=q) | Q(description__icontains=q) | Q(user__icontains=q))
        # Worst first, then most recent: a critical sign-in never sits under a medium.
        rank = Case(
            *[When(severity=s, then=Value(i)) for i, s in enumerate(["info", "low", "medium", "high", "critical"])],
            default=Value(0), output_field=IntegerField(),
        )
        return queryset.annotate(severity_rank=rank).order_by("-severity_rank", "-last_seen")

    @extend_schema(request=None, responses={200: LogDetectionSerializer})
    @action(detail=True, methods=["post"])
    def resolve(self, request, pk=None):
        """Marks it dealt with (or back to open with {"reopen": true}). Analyst or higher."""
        detection = self.get_object()
        require_org_role(request.user, detection.organization, Membership.Role.ANALYST)
        if request.data.get("reopen"):
            detection.status, detection.resolved_at, detection.resolved_by = LogDetection.Status.OPEN, None, None
        else:
            detection.status = LogDetection.Status.RESOLVED
            detection.resolved_at = timezone.now()
            detection.resolved_by = request.user
            record_activity(
                request.user, detection.organization, ActivityEvent.Verb.DETECTION_RESOLVED,
                f"Resolved '{detection.title}' on {detection.source.name}",
            )
        detection.save(update_fields=["status", "resolved_at", "resolved_by"])
        return Response(LogDetectionSerializer(detection).data)


class ErrorGroupViewSet(OrgScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    """
    GET /api/error-groups/?organization=<id>&status=unresolved
    Application errors, each repeat of the same error counted in one group.
    """

    queryset = ErrorGroup.objects.select_related("source")
    serializer_class = ErrorGroupSerializer
    org_field = "organization"

    def get_queryset(self):
        params = self.request.query_params
        queryset = super().get_queryset()
        for field in ("organization", "source"):
            if params.get(field):
                queryset = queryset.filter(**{f"{field}_id": params[field]})
        if params.get("status"):
            queryset = queryset.filter(status=params["status"])
        if params.get("release"):
            queryset = queryset.filter(first_release=params["release"])
        if params.get("q"):
            q = params["q"].strip()
            queryset = queryset.filter(
                Q(title__icontains=q) | Q(exception_type__icontains=q) | Q(culprit__icontains=q) | Q(service__icontains=q)
            )
        order = {"count": "-count", "new": "-first_seen"}.get(params.get("sort", ""), "-last_seen")
        return queryset.order_by(order)

    @extend_schema(request=None, responses={200: ErrorGroupSerializer})
    @action(detail=True, methods=["post"], url_path="set-status")
    def set_status(self, request, pk=None):
        """{"status": "resolved" | "ignored" | "unresolved"}. Analyst or higher."""
        group = self.get_object()
        require_org_role(request.user, group.organization, Membership.Role.ANALYST)
        status_value = request.data.get("status")
        if status_value not in ErrorGroup.Status.values:
            raise ValidationError({"status": ["Choose resolved, ignored or unresolved."]})
        group.status = status_value
        group.resolved_at = timezone.now() if status_value == ErrorGroup.Status.RESOLVED else None
        group.save(update_fields=["status", "resolved_at"])
        return Response(ErrorGroupSerializer(group).data)


    @extend_schema(parameters=[OpenApiParameter("organization", OpenApiTypes.UUID, required=True)],
                   responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["get"])
    def releases(self, request):
        """
        The applications' recent releases (last 30 days, newest first): when
        each started logging, and how many errors first appeared in it.
        """
        organization = Organization.objects.filter(id=request.query_params.get("organization")).first()
        if organization is None or not user_can_access_org(request.user, organization):
            raise ValidationError({"organization": ["Choose one of your organizations."]})
        since = timezone.now() - timedelta(days=30)
        rows = (
            LogEvent.objects.filter(organization=organization, occurred_at__gte=since).exclude(release="")
            .values("source_id", "source__name", "release")
            .annotate(first_seen=Min("occurred_at"), last_seen=Max("occurred_at"), events=Count("id"),
                      errors=Count("id", filter=Q(category=LogEvent.Category.APP_ERROR)))
            .order_by("-first_seen")[:20]
        )
        introduced = dict(
            ((source, release), n) for source, release, n in
            ErrorGroup.objects.filter(organization=organization).exclude(first_release="")
            .values_list("source_id", "first_release").annotate(n=Count("id"))
        )
        return Response([
            {"source": row["source_id"], "source_name": row["source__name"], "release": row["release"],
             "first_seen": row["first_seen"], "last_seen": row["last_seen"], "events": row["events"],
             "errors": row["errors"], "new_errors": introduced.get((row["source_id"], row["release"]), 0)}
            for row in rows
        ])


class LogAlertRuleViewSet(OrgScopedQuerysetMixin, viewsets.ModelViewSet):
    """
    The organization's own log alerts: "<text> seen <n> times within <m>
    minutes". Everyone can see them; analysts and above manage them.
    """

    queryset = LogAlertRule.objects.select_related("source", "created_by")
    serializer_class = LogAlertRuleSerializer
    org_field = "organization"
    pagination_class = None

    def get_queryset(self):
        queryset = super().get_queryset()
        organization = self.request.query_params.get("organization")
        return queryset.filter(organization_id=organization) if organization else queryset

    def perform_create(self, serializer):
        organization = serializer.validated_data["organization"]
        if not user_can_access_org(self.request.user, organization):
            raise PermissionDenied("You are not a member of this organization.")
        require_org_role(self.request.user, organization, Membership.Role.ANALYST)
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        require_org_role(self.request.user, serializer.instance.organization, Membership.Role.ANALYST)
        serializer.save()

    def perform_destroy(self, instance):
        require_org_role(self.request.user, instance.organization, Membership.Role.ANALYST)
        instance.delete()

    @extend_schema(request=LogAlertRuleSerializer, responses={200: OpenApiTypes.OBJECT})
    @action(detail=False, methods=["post"])
    def preview(self, request):
        """What an alert (not yet saved) would have matched in the last 24 hours, with examples."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organization = serializer.validated_data["organization"]
        if not user_can_access_org(request.user, organization):
            raise PermissionDenied("You are not a member of this organization.")
        rule = LogAlertRule(**serializer.validated_data)
        recent = rule.events().filter(occurred_at__gte=timezone.now() - timedelta(hours=24))
        return Response({
            "matches_24h": recent.count(),
            "examples": LogEventSerializer(recent.select_related("source")[:3], many=True).data,
        })


class LogOverviewView(APIView):
    """
    GET /api/logs/overview/?organization=<id>
    The numbers for the top of the Server logs page, plus the list of
    what the built-in detections watch for.
    """

    @extend_schema(parameters=[OpenApiParameter("organization", OpenApiTypes.UUID, required=True)],
                   responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        organization = Organization.objects.filter(id=request.query_params.get("organization")).first()
        if organization is None or not user_can_access_org(request.user, organization):
            raise ValidationError({"organization": ["Choose one of your organizations."]})
        since = timezone.now() - timedelta(hours=24)
        events = LogEvent.objects.filter(organization=organization, occurred_at__gte=since)
        by_category = dict(events.values_list("category").annotate(n=Count("id")))
        sources = list(LogSource.objects.filter(organization=organization))
        open_detections = LogDetection.objects.filter(organization=organization, status=LogDetection.Status.OPEN)
        return Response({
            "events_24h": sum(by_category.values()),
            "by_category_24h": {c: by_category.get(c, 0) for c in LogEvent.Category.values},
            "failed_signins_24h": by_category.get(LogEvent.Category.AUTH_FAILURE, 0),
            "sources": {
                "total": len(sources),
                "receiving": sum(1 for s in sources if s.status == "receiving"),
                "silent": sum(1 for s in sources if s.status == "silent"),
                "waiting": sum(1 for s in sources if s.status == "waiting"),
            },
            "open_detections": open_detections.count(),
            "applications": sum(1 for s in sources if s.is_application),
            "errors_24h": by_category.get(LogEvent.Category.APP_ERROR, 0),
            "server_errors_24h": events.filter(http_status__gte=500).count(),
            "unresolved_errors": ErrorGroup.objects.filter(
                organization=organization, status=ErrorGroup.Status.UNRESOLVED
            ).count(),
            "open_by_severity": dict(open_detections.values_list("severity").annotate(n=Count("id"))),
            "top_attackers_24h": [
                {"ip": ip, "failures": n}
                for ip, n in events.filter(category=LogEvent.Category.AUTH_FAILURE, src_ip__isnull=False)
                .values_list("src_ip").annotate(n=Count("id")).order_by("-n")[:5]
            ],
            "retention_days": organization.log_retention_days,
            "rules": [
                {"rule": rule, "severity": severity, "title": title, "description": description}
                for rule, severity, title, description in RULES
            ],
        })


CLIENT_FILES = {
    "densight_logging.py": "text/x-python",
    "densight-logger.js": "text/javascript",
    "DensightHandler.php": "text/x-php",
    "densight_logger.rb": "text/x-ruby",
    "densight.go": "text/x-go",
}


def client_file(request, name):
    """
    GET /api/logs/clients/<name> -- the small open-source senders for
    Python and Node.js apps (apps/logs/clients). Plain code with no
    secrets in it, so it needs no sign-in: it can be fetched with curl
    straight onto the server.
    """
    if name not in CLIENT_FILES:
        raise Http404
    path = Path(__file__).resolve().parent / "clients" / name
    return FileResponse(path.open("rb"), content_type=CLIENT_FILES[name], as_attachment=True, filename=name)
