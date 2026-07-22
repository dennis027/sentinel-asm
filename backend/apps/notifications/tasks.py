"""
Notification dispatch. Called from apps.scanning.tasks.run_scan_job
after a scan completes, with the IDs of findings that were genuinely
NEW this run (not just re-confirmed) -- re-confirming an unchanged
finding every day should never re-send an email.
"""

from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail

from apps.findings.models import Finding

from .models import NotificationRule
from apps.scanning.metrics import NOTIFICATIONS_SENT_TOTAL

# Ordering, low to high -- used to compare a finding's severity against
# a rule's min_severity threshold.
SEVERITY_ORDER = {
    Finding.Severity.INFO: 0,
    Finding.Severity.LOW: 1,
    Finding.Severity.MEDIUM: 2,
    Finding.Severity.HIGH: 3,
    Finding.Severity.CRITICAL: 4,
}


@shared_task
def notify_new_findings(scan_job_id: str, finding_ids: list[str]):
    if not finding_ids:
        return "No new findings -- nothing to notify."

    findings = list(
        Finding.objects.filter(id__in=finding_ids).select_related("asset", "asset__organization")
    )
    if not findings:
        return "Finding IDs no longer exist -- nothing to notify."

    organization = findings[0].asset.organization
    rules = NotificationRule.objects.filter(organization=organization, is_active=True)
    if not rules:
        return f"No active notification rules for {organization.name}."

    sent_count = 0
    for rule in rules:
        threshold = SEVERITY_ORDER[rule.min_severity]
        matching = [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]
        if not matching:
            continue
        _send_digest_email(rule.recipient_email, organization, matching)
        sent_count += 1
        NOTIFICATIONS_SENT_TOTAL.inc()

    return f"Sent {sent_count} notification email(s) for {len(findings)} new finding(s)."


def _send_digest_email(recipient_email: str, organization, findings: list[Finding]):
    finding_lines = "\n".join(
        f"  - [{f.severity.upper()}] {f.title} ({f.asset.value})" for f in findings
    )
    subject = f"[Sentinel ASM] {len(findings)} new finding(s) for {organization.name}"
    body = (
        f"New findings detected for {organization.name}:\n\n"
        f"{finding_lines}\n\n"
        f"Log in to review details and mark findings as accepted/false-positive."
    )
    send_mail(
        subject=subject,
        message=body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient_email],
        fail_silently=False,
    )