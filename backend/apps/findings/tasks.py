from celery import shared_task
from django.utils import timezone

from apps.audit_logs.activity import record as record_activity
from apps.audit_logs.models import ActivityEvent
from apps.organizations.models import Organization

from .models import Finding
from .summary import build_risk_summary, record_snapshot


@shared_task
def record_risk_snapshots():
    """
    Daily (celery-beat): records every organization's numbers, so the
    trend has a point for each day even when nobody opened the dashboard.
    """
    count = 0
    for organization in Organization.objects.filter(is_active=True):
        record_snapshot(organization, build_risk_summary(organization))
        count += 1
    return f"Recorded risk snapshots for {count} organization(s)."


@shared_task
def expire_risk_acceptances():
    """
    Daily (celery-beat): a risk accepted "until" a date that has now
    passed goes back to open, so it counts toward the grade again and
    someone has to look at it afresh.
    """
    today = timezone.localdate()
    expired = Finding.objects.filter(
        status=Finding.Status.ACCEPTED, accepted_until__isnull=False, accepted_until__lte=today
    ).select_related("asset__organization")
    count = 0
    for finding in expired:
        until = finding.accepted_until
        finding.status = Finding.Status.OPEN
        finding.status_note = f"Risk acceptance ended on {until.isoformat()}."
        finding.status_changed_at = timezone.now()
        finding.status_changed_by = None
        finding.accepted_until = None
        finding.save(update_fields=[
            "status", "status_note", "status_changed_at", "status_changed_by", "accepted_until",
        ])
        record_activity(
            None, finding.asset.organization, ActivityEvent.Verb.ACCEPTANCE_EXPIRED,
            f"Risk acceptance for '{finding.title}' on {finding.asset.value} ended; it is open again",
            finding=finding,
        )
        count += 1
    return f"Reopened {count} finding(s) whose risk acceptance ended."
