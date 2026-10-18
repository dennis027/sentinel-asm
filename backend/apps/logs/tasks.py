from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from apps.notifications.models import NotificationRule
from apps.notifications.tasks import SEVERITY_ORDER, _post_text

from .detections import analyze, check_silent_sources
from .models import ErrorGroup, LogEvent, LogSource


@shared_task
def analyze_events(source_id: str, first_id: int, last_id: int, new_group_ids=(), regressed_group_ids=()):
    """Runs the detections over one stored batch and alerts on anything new."""
    source = LogSource.objects.filter(id=source_id).select_related("organization").first()
    if source is None:
        return "Source gone."
    events = list(LogEvent.objects.filter(source=source, id__gte=first_id, id__lte=last_id).order_by("occurred_at"))
    detections = analyze(
        source, events,
        new_groups=list(ErrorGroup.objects.filter(id__in=new_group_ids or [])),
        regressed_groups=list(ErrorGroup.objects.filter(id__in=regressed_group_ids or [])),
    )
    for detection in detections:
        notify(detection)
    return f"Analysed {len(events)} event(s); {len(detections)} new detection(s)."


@shared_task
def check_log_sources():
    """Every few minutes (celery-beat): flags servers that stopped sending logs."""
    detections = check_silent_sources()
    for detection in detections:
        notify(detection)
    return f"{len(detections)} server(s) went quiet."


@shared_task
def purge_old_log_events():
    """Daily (celery-beat): deletes events older than each organization's retention."""
    from apps.organizations.models import Organization

    deleted = 0
    for organization in Organization.objects.all().only("id", "log_retention_days"):
        cutoff = timezone.now() - timedelta(days=organization.log_retention_days)
        count, _ = LogEvent.objects.filter(organization=organization, occurred_at__lt=cutoff).delete()
        deleted += count
    return f"Deleted {deleted} old log event(s)."


def notify(detection) -> int:
    """Tells the organization's alert rules about a new detection, by the same severity thresholds."""
    organization = detection.source.organization
    rules = NotificationRule.objects.filter(organization=organization, is_active=True)
    rank = SEVERITY_ORDER.get(detection.severity, 0)
    when = timezone.localtime(detection.last_seen).strftime("%d %b %H:%M")
    text = (
        f"🚨 {detection.title} on {detection.source.name} ({organization.name}), {detection.severity}, {when}.\n"
        f"{detection.description[:500]}"
    )
    sent = 0
    for rule in rules:
        if rank < SEVERITY_ORDER[rule.min_severity]:
            continue
        if rule.channel == NotificationRule.Channel.WEBHOOK:
            sent += _post_text(rule.webhook_url, text, organization)
        else:
            send_mail(
                subject=f"Densight: {detection.title} on {detection.source.name}",
                message=(
                    f"Hello,\n\nDensight found something in the logs from {detection.source.name}:\n\n"
                    f"  {detection.severity.upper()}  {detection.title}\n  {when}\n\n{detection.description}\n\n"
                    f"What to do next: sign in to Densight, open Server logs, and look at the events around it.\n\n"
                    f"--\nYou get this because {organization.name} has an alert for this severity sent to this address."
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[rule.recipient_email],
                fail_silently=True,
            )
            sent += 1
    return sent


