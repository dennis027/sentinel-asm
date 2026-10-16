"""
Notification dispatch. Called from apps.scanning.tasks.run_scan_job
after a scan completes, with the IDs of findings that were genuinely
NEW this run (not just re-confirmed) -- re-confirming an unchanged
finding every day should never re-send an email.
"""

import json
import logging
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from celery import shared_task
from django.conf import settings
from django.core.mail import EmailMessage, send_mail
from django.utils import timezone

from apps.scanning.targets import TargetNotAllowed, assert_public_target

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
        if rule.channel == NotificationRule.Channel.WEBHOOK:
            # One unreachable chat webhook must not stop the email
            # rules after it from being sent.
            if not _post_webhook(rule.webhook_url, organization, matching):
                continue
        else:
            _send_digest_email(rule.recipient_email, organization, matching, rule)
        sent_count += 1
        NOTIFICATIONS_SENT_TOTAL.inc()

    return f"Sent {sent_count} notification(s) for {len(findings)} new finding(s)."


# What a rule's threshold means, in words people use.
THRESHOLD_WORDS = {
    Finding.Severity.CRITICAL: "critical issues only",
    Finding.Severity.HIGH: "critical and high issues",
    Finding.Severity.MEDIUM: "medium, high and critical issues",
    Finding.Severity.LOW: "every issue except informational ones",
    Finding.Severity.INFO: "every new finding",
}


def _issues_phrase(count: int) -> str:
    return f"{count} new security issue" + ("" if count == 1 else "s")


def _send_digest_email(recipient_email: str, organization, findings: list[Finding], rule=None):
    lines = "\n\n".join(
        f"  {f.severity.upper():<9} {f.title}\n            on {f.asset.value}" for f in findings
    )
    threshold = THRESHOLD_WORDS.get(rule.min_severity if rule else "", "new issues")
    subject = f"Densight: {_issues_phrase(len(findings))} on {organization.name}"
    body = (
        f"Hello,\n\n"
        f"The latest scan of {organization.root_domain} found {_issues_phrase(len(findings))} "
        f"you asked to hear about:\n\n"
        f"{lines}\n\n"
        f"What to do next: sign in to Densight, open Findings, and give each issue an owner. "
        f"Each one says why it matters and how to fix it.\n\n"
        f"--\n"
        f"You get this because {organization.name} has an alert for {threshold} sent to this address. "
        f"An admin can change or pause it under Alerts & reports."
    )
    send_mail(
        subject=subject,
        message=body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient_email],
        fail_silently=False,
    )

logger = logging.getLogger("apps.notifications")

WEBHOOK_TIMEOUT_SECONDS = 10
WEBHOOK_MAX_LISTED = 15


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A webhook that answers with a redirect is refused rather than
    followed: the address was vetted, wherever it points next was not."""

    def redirect_request(self, *args, **kwargs):
        return None


def _post_webhook(url: str, organization, findings: list[Finding]) -> bool:
    """Posts the new findings to a chat webhook. Returns whether it was delivered."""
    listed = findings[:WEBHOOK_MAX_LISTED]
    lines = [f"• [{f.severity.upper()}] {f.title} ({f.asset.value})" for f in listed]
    if len(findings) > len(listed):
        lines.append(f"…and {len(findings) - len(listed)} more.")
    text = f"{_issues_phrase(len(findings))} on {organization.name}:\n" + "\n".join(lines)
    return _post_text(url, text, organization)


def _post_text(url: str, text: str, organization) -> bool:
    """POSTs {"text": ...}, the message format Slack, Teams workflows and Mattermost accept."""
    try:
        # Checked again at send time: DNS for the host may have changed
        # since the rule was saved.
        assert_public_target(urlsplit(url).hostname or "")
    except TargetNotAllowed as exc:
        logger.warning("webhook_refused", extra={"reason": str(exc)})
        return False

    request = urllib.request.Request(
        url,
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "densight/1.0"},
        method="POST",
    )
    try:
        with urllib.request.build_opener(_NoRedirects).open(request, timeout=WEBHOOK_TIMEOUT_SECONDS):
            return True
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        logger.warning("webhook_failed", extra={"organization_id": str(organization.id), "error": str(exc)})
        return False


def send_test_alert(rule) -> tuple[bool, str]:
    """
    Sends a clearly-marked test message to the rule's destination right
    away (not through the queue), so whoever set it up can see at once
    whether it arrives. Returns (delivered, what to tell the person).
    """
    organization = rule.organization
    threshold = THRESHOLD_WORDS.get(rule.min_severity, "new issues")
    if rule.channel == NotificationRule.Channel.WEBHOOK:
        text = (
            f"✅ Test from Densight: this channel will be told about {threshold} "
            f"found on {organization.name} ({organization.root_domain})."
        )
        if _post_text(rule.webhook_url, text, organization):
            return True, "Test message sent. Check the channel: it should be there now."
        return False, (
            "The chat service didn't accept the message. Check the link is a current incoming-webhook "
            "address (it may have been revoked) and try again."
        )
    try:
        send_mail(
            subject=f"Densight: test alert for {organization.name}",
            message=(
                f"Hello,\n\nThis is a test. From now on this address will get an email whenever a scan of "
                f"{organization.root_domain} finds {threshold}.\n\n"
                f"Nothing needs doing. If this landed in spam, mark it as not spam so real alerts arrive."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[rule.recipient_email],
            fail_silently=False,
        )
    except Exception as exc:  # the mail server's own error is what helps here
        logger.warning("test_email_failed", extra={"error": str(exc)})
        return False, f"The email could not be sent: {exc}"
    return True, f"Test email sent to {rule.recipient_email}. It can take a minute to arrive; check spam too."


@shared_task
def send_weekly_report(organization_id: str, recipients: list[str]):
    """
    Emails the organization's PDF report -- the same one "Download
    report" produces -- with the plain-English summary in the body, so
    the people who most need the picture don't have to log in to get it.
    """
    from apps.findings.models import Finding
    from apps.findings.remediation import remediation_metrics
    from apps.findings.reports import generate_executive_report
    from apps.findings.summary import build_changes, build_narrative, build_risk_summary, build_trend
    from apps.organizations.models import Organization

    organization = Organization.objects.filter(id=organization_id).first()
    if organization is None or not recipients:
        return "Nothing to send."

    summary = build_risk_summary(organization)
    changes = build_changes(organization, 7)
    remediation = remediation_metrics(organization)
    narrative = build_narrative(organization, summary, changes, remediation, build_trend(organization, 90))
    top_issues = list(
        Finding.objects.counts_toward_risk()
        .filter(asset__organization=organization, asset__is_active=True)
        .select_related("asset")
        .by_severity()[:10]
    )
    pdf = generate_executive_report(organization, summary, changes, top_issues, narrative, remediation)

    message = EmailMessage(
        subject=f"Densight weekly report for {organization.name}: grade {summary['average_risk_grade'] or 'n/a'}",
        body="\n\n".join([
            f"Weekly attack surface report for {organization.name} ({organization.root_domain}).",
            " ".join(narrative),
            "The full report, with what to fix first and why, is attached.",
        ]),
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=recipients,
    )
    message.attach(
        f"{organization.root_domain}-report-{timezone.now():%Y%m%d}.pdf", pdf, "application/pdf"
    )
    message.send(fail_silently=False)
    return f"Sent the weekly report for {organization.name} to {len(recipients)} recipient(s)."


@shared_task
def send_weekly_reports():
    """Monday morning (celery-beat): one report per organization, to every opted-in email rule."""
    recipients: dict[str, list[str]] = {}
    for rule in NotificationRule.objects.filter(
        is_active=True, weekly_report=True, channel=NotificationRule.Channel.EMAIL
    ).exclude(recipient_email=""):
        recipients.setdefault(str(rule.organization_id), []).append(rule.recipient_email)
    for organization_id, emails in recipients.items():
        send_weekly_report.delay(organization_id, sorted(set(emails)))
    return f"Queued weekly reports for {len(recipients)} organization(s)."
