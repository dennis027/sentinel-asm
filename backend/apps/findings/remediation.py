"""
Fix-by dates and the numbers that show whether issues get fixed.

The deadline for a finding is when it was first seen plus its
severity's SLA: the organization's own policy where it has one
(Organization.sla_policy), the server default otherwise
(settings.REMEDIATION_SLA_DAYS). It is computed rather than stored, so
a change of policy applies to every open finding.
"""

from datetime import timedelta

from django.conf import settings
from django.db.models import Avg, DurationField, ExpressionWrapper, F, Q
from django.utils import timezone

from .models import Finding

MTTR_WINDOW_DAYS = 90


def due_at(finding, sla: dict | None = None):
    if sla is None:
        sla = finding.asset.organization.sla_policy
    days = sla.get(finding.severity)
    if days is None:
        return None
    return finding.first_seen + timedelta(days=days)


def is_overdue(finding, now=None, sla: dict | None = None) -> bool:
    if not finding.is_active or finding.status != Finding.Status.OPEN:
        return False
    deadline = due_at(finding, sla)
    return deadline is not None and deadline < (now or timezone.now())


def overdue_q(now=None, sla: dict | None = None) -> Q:
    """Database filter for open findings past their fix-by date under one SLA policy."""
    now = now or timezone.now()
    past_deadline = Q(pk__in=[])  # matches nothing; OR-ed with each severity below
    for severity, days in (sla or settings.REMEDIATION_SLA_DAYS).items():
        past_deadline |= Q(severity=severity, first_seen__lt=now - timedelta(days=days))
    return Q(is_active=True, status=Finding.Status.OPEN) & past_deadline


def overdue_q_for(organizations, now=None) -> Q:
    """overdue_q across several organizations, each under its own policy."""
    condition = Q(pk__in=[])
    for organization in organizations:
        condition |= Q(asset__organization=organization) & overdue_q(now, organization.sla_policy)
    return condition


def remediation_metrics(organization) -> dict:
    """
    Overdue, unassigned and mean-time-to-fix figures for the dashboard
    and the reports. Issues only -- inventory findings have no deadline.
    """
    issues = Finding.objects.filter(asset__organization=organization).exclude(
        finding_type__in=Finding.INVENTORY_TYPES
    )
    open_issues = issues.counts_toward_risk()
    since = timezone.now() - timedelta(days=MTTR_WINDOW_DAYS)
    fixed = issues.filter(is_active=False, resolved_at__gte=since)
    mean_time = fixed.annotate(
        time_to_fix=ExpressionWrapper(F("resolved_at") - F("first_seen"), output_field=DurationField())
    ).aggregate(mean=Avg("time_to_fix"))["mean"]

    return {
        "overdue": open_issues.filter(overdue_q(sla=organization.sla_policy)).count(),
        "unassigned_critical_high": open_issues.filter(
            assignee__isnull=True, severity__in=[Finding.Severity.CRITICAL, Finding.Severity.HIGH]
        ).count(),
        "assigned": open_issues.filter(assignee__isnull=False).count(),
        "fixed_last_90_days": fixed.count(),
        "mean_days_to_fix": round(mean_time.total_seconds() / 86400, 1) if mean_time else None,
        "sla_days": organization.sla_policy,
    }
