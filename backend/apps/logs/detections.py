"""
The built-in detections: suspicious things found in server logs.

Each rule looks at a batch of newly stored events (plus a short window
of earlier ones where it needs to count) and reports Hits. A hit for
the same rule, server and subject (an address, a user) as an open
detection seen in the last day updates that detection instead of
creating another, so a week-long brute-force campaign is one item, not
thousands.
"""

from dataclasses import dataclass
from datetime import timedelta

from django.db.models import Count, Max, Min
from django.utils import timezone

from .models import LogAlertRule, LogDetection, LogEvent

C = LogEvent.Category
WINDOW = timedelta(minutes=10)
BRUTE_FORCE_THRESHOLD = 10
SPRAY_USERS = 5
COMPROMISE_FAILURES = 5
MERGE_WITHIN = timedelta(days=1)
SPIKE_WINDOW = timedelta(minutes=5)
ERROR_SPIKE = 50
SERVER_ERROR_SPIKE = 25
PROBES_FROM_ONE_ADDRESS = 5
# More new errors than this in one batch become one detection, not a flood.
NEW_ERRORS_LISTED = 5


@dataclass
class Hit:
    rule: str
    key: str
    severity: str
    title: str
    description: str
    events: int
    first_seen: object
    last_seen: object
    user: str = ""
    src_ip: str | None = None


# Shown on the page that lists what Densight watches for.
RULES = [
    ("brute_force", "high", "Many failed sign-ins from one address",
     f"{BRUTE_FORCE_THRESHOLD} or more failed SSH, RDP, Windows or app sign-ins (a login endpoint answering "
     "401/403) from one address within 10 minutes: password guessing or credential stuffing."),
    ("password_spray", "high", "One address trying many accounts",
     f"Failed sign-ins for {SPRAY_USERS} or more different users from one address within 10 minutes."),
    ("login_after_failures", "critical", "Successful sign-in after repeated failures",
     f"A sign-in that worked, from an address with {COMPROMISE_FAILURES} or more failures in the hour before: "
     "the password may have been guessed."),
    ("root_login", "high", "Direct sign-in as root",
     "Someone signed in over SSH as root, which bypasses personal accounts and their audit trail."),
    ("admin_added", "high", "New administrator",
     "An account was added to sudo, wheel or Administrators."),
    ("account_created", "medium", "New user account", "A local or domain account was created."),
    ("logs_cleared", "critical", "Logs cleared",
     "A security log was cleared or log files were deleted: a common step to hide an intrusion."),
    ("sudo_denied", "medium", "Blocked attempt to use admin rights",
     "Someone not allowed to use sudo tried to."),
    ("service_installed", "medium", "New service or scheduled task",
     "A service or scheduled task was installed: how many attackers keep a foothold."),
    ("account_locked_out", "medium", "Account locked out",
     "Too many wrong passwords locked an account; someone may be guessing it."),
    ("source_silent", "medium", "Server stopped sending logs",
     "No logs have arrived for a while: the shipper stopped, the server is down, or logging was turned off."),
    ("secrets_logged", "high", "Secrets written to logs",
     "A password, API key, token or card number appeared in a log. It was masked before storing, but the code "
     "that logged it should be fixed: other copies of the log may not be."),
    ("new_error", "medium", "New error in an application",
     "An error the application has not had before: often a fresh bug from the latest release."),
    ("error_regressed", "medium", "Fixed error came back",
     "An error marked as resolved is happening again."),
    ("error_spike", "high", "Error spike",
     f"{ERROR_SPIKE} or more application errors within 5 minutes."),
    ("server_errors_spike", "high", "Burst of server errors (5xx)",
     f"{SERVER_ERROR_SPIKE} or more requests answered with a 5xx status within 5 minutes: the site is failing "
     "for visitors."),
    ("attack_probes", "medium", "Attack probes against an application",
     f"{PROBES_FROM_ONE_ADDRESS} or more requests from one address that look like attacks (SQL injection, path "
     "traversal, Log4Shell, scanning tools) within 10 minutes."),
]
RULE_INFO = {rule: (severity, title) for rule, severity, title, _ in RULES}


def analyze(source, events: list[LogEvent], new_groups=None, regressed_groups=None) -> list[LogDetection]:
    """Runs every rule over a new batch of events; returns detections that are new."""
    if new_groups is None:
        new_groups = getattr(events, "new_groups", [])
    if regressed_groups is None:
        regressed_groups = getattr(events, "regressed_groups", [])
    if not events:
        return []
    hits: list[Hit] = []
    hits += _counting_rules(source, events)
    hits += _single_event_rules(events)
    hits += _secret_rules(events)
    hits += _app_rules(source, events, new_groups, regressed_groups)
    hits += _custom_rules(source, events)
    return [detection for detection in (_record(source, hit) for hit in hits) if detection is not None]


def _secret_rules(events: list[LogEvent]) -> list[Hit]:
    by_kind: dict = {}
    for event in events:
        for kind in event.redacted or []:
            by_kind.setdefault(kind, []).append(event)
    labels = {"aws_key": "AWS access key", "private_key": "private key", "jwt": "session token (JWT)",
              "bearer_token": "bearer token", "password": "password", "secret": "secret or API key",
              "card_number": "card number", "github_token": "GitHub token", "slack_token": "Slack token",
              "stripe_key": "Stripe key"}
    hits = []
    for kind, matching in by_kind.items():
        sample = matching[-1]
        where = f"{sample.service or sample.program or sample.host or 'a log'}"
        hits.append(Hit(
            "secrets_logged", kind, "high", f"A {labels.get(kind, kind)} was written to the logs ({where})",
            f"{len(matching)} log line(s) contained a {labels.get(kind, kind)}; it was masked before storing. Fix the "
            f"code that logs it, and treat the {labels.get(kind, kind)} as exposed if logs are kept elsewhere too. "
            f"Example (masked): {sample.message[:300]}",
            len(matching), matching[0].occurred_at, sample.occurred_at,
        ))
    return hits


def _app_rules(source, events, new_groups, regressed_groups) -> list[Hit]:
    hits = []
    if len(new_groups) > NEW_ERRORS_LISTED:
        first = min(g.first_seen for g in new_groups)
        last = max(g.last_seen for g in new_groups)
        names = ", ".join(sorted({g.exception_type or "Error" for g in new_groups})[:6])
        hits.append(Hit("new_error", f"batch:{first.isoformat()}", "medium",
                        f"{len(new_groups)} new errors in {source.name}",
                        f"{len(new_groups)} errors not seen before ({names}). Check the latest release.",
                        len(new_groups), first, last))
    else:
        for group in new_groups:
            hits.append(Hit(
                "new_error", group.fingerprint, "medium",
                f"New error in {group.service or source.name}: {group.exception_type or 'Error'}"
                + (f" (release {group.first_release})" if group.first_release else ""),
                f"{group.title}\n{group.culprit}".strip()
                + (f"\nFirst seen in release {group.first_release}." if group.first_release else ""),
                group.count, group.first_seen, group.last_seen,
            ))
    for group in regressed_groups:
        hits.append(Hit(
            "error_regressed", group.fingerprint, "medium",
            f"Resolved error came back in {group.service or source.name}: {group.exception_type or 'Error'}"
            + (f" (release {group.last_release})" if group.last_release else ""),
            f"{group.title}\n{group.culprit}".strip()
            + (f"\nCame back in release {group.last_release}"
               + (f"; it first appeared in {group.first_release}." if group.first_release
                  and group.first_release != group.last_release else ".") if group.last_release else ""),
            group.count, group.last_seen, group.last_seen,
        ))

    errors = [e for e in events if e.category == C.APP_ERROR]
    if errors:
        latest = max(e.occurred_at for e in errors)
        window = LogEvent.objects.filter(source=source, category=C.APP_ERROR,
                                         occurred_at__gte=latest - SPIKE_WINDOW, occurred_at__lte=latest)
        stats = window.aggregate(n=Count("id"), first=Min("occurred_at"))
        if stats["n"] >= ERROR_SPIKE:
            hits.append(Hit("error_spike", "", "high", f"Error spike in {source.name}: {stats['n']} errors in 5 minutes",
                            f"{stats['n']} application errors within 5 minutes on {source.name}.",
                            stats["n"], stats["first"], latest))

    failures = [e for e in events if (e.http_status or 0) >= 500]
    if failures:
        latest = max(e.occurred_at for e in failures)
        window = LogEvent.objects.filter(source=source, http_status__gte=500,
                                         occurred_at__gte=latest - SPIKE_WINDOW, occurred_at__lte=latest)
        stats = window.aggregate(n=Count("id"), first=Min("occurred_at"))
        if stats["n"] >= SERVER_ERROR_SPIKE:
            hits.append(Hit("server_errors_spike", "", "high",
                            f"{stats['n']} server errors (5xx) in 5 minutes on {source.name}",
                            "Visitors are getting error pages. Check the application and what it depends on "
                            "(database, other services).", stats["n"], stats["first"], latest))

    probes_by_ip: dict = {}
    for event in events:
        if event.action == "attack_probe" and event.src_ip:
            probes_by_ip[event.src_ip] = max(probes_by_ip.get(event.src_ip, event.occurred_at), event.occurred_at)
    for ip, latest in probes_by_ip.items():
        window = LogEvent.objects.filter(source=source, action="attack_probe", src_ip=ip,
                                         occurred_at__gte=latest - WINDOW, occurred_at__lte=latest)
        count = window.count()
        if count >= PROBES_FROM_ONE_ADDRESS:
            samples = "; ".join(window.order_by("-occurred_at").values_list("message", flat=True)[:4])
            hits.append(Hit("attack_probes", ip, "medium", f"Attack probes from {ip} against {source.name}",
                            f"{count} attack-like requests within 10 minutes, e.g. {samples[:400]}",
                            count, window.aggregate(first=Min("occurred_at"))["first"], latest, src_ip=ip))
    return hits


def _custom_rules(source, events: list[LogEvent]) -> list[Hit]:
    """The organization's own rules: <text> seen <threshold> times within <window>."""
    hits = []
    rules = LogAlertRule.objects.filter(organization_id=source.organization_id, enabled=True)
    for rule in rules:
        matching = [e for e in events if rule.matches(e)]
        if not matching:
            continue
        latest = max(e.occurred_at for e in matching)
        window = rule.events().filter(occurred_at__gte=latest - timedelta(minutes=rule.window_minutes),
                                      occurred_at__lte=latest)
        if rule.source_id is None:
            # Counted per source, so each detection points at one place.
            window = window.filter(source=source)
        if rule.threshold > 1:
            stats = window.aggregate(n=Count("id"), first=Min("occurred_at"))
            count, first_seen = stats["n"], stats["first"]
        else:
            count, first_seen = len(matching), min(e.occurred_at for e in matching)
        if count < rule.threshold:
            continue
        sample = matching[-1].message[:300]
        what = f"\"{rule.contains}\"" if rule.contains else "matching events"
        hits.append(Hit(
            rule.rule_id, "", rule.severity, f"{rule.name}: {count} on {source.name}",
            f"Your rule \"{rule.name}\" ({what}, {rule.threshold} or more within {rule.window_minutes} min) "
            f"matched {count} event(s) on {source.name}. Latest: {sample}",
            count, first_seen, latest,
        ))
        LogAlertRule.objects.filter(id=rule.id).update(last_fired_at=latest)
    return hits


def _counting_rules(source, events: list[LogEvent]) -> list[Hit]:
    hits = []
    failures = [e for e in events if e.category == C.AUTH_FAILURE and e.src_ip]
    successes = [e for e in events if e.category == C.AUTH_SUCCESS and e.src_ip]
    if not failures and not successes:
        return hits
    # Each address is counted over the 10 minutes up to its own latest
    # failure in the batch -- a batch can span hours (a shipper catching
    # up after an outage), and a burst early in it must still be seen.
    latest_by_ip: dict = {}
    for event in failures:
        latest_by_ip[event.src_ip] = max(latest_by_ip.get(event.src_ip, event.occurred_at), event.occurred_at)

    for ip, latest in latest_by_ip.items():
        window = LogEvent.objects.filter(
            source=source, category=C.AUTH_FAILURE, src_ip=ip,
            occurred_at__gte=latest - WINDOW, occurred_at__lte=latest,
        )
        stats = window.aggregate(n=Count("id"), users=Count("user", distinct=True), first=Min("occurred_at"),
                                 last=Max("occurred_at"))
        if stats["n"] >= BRUTE_FORCE_THRESHOLD:
            hits.append(Hit(
                "brute_force", ip, "high", f"Many failed sign-ins from {ip}",
                f"{stats['n']} failed sign-ins from {ip} on {source.name} within 10 minutes.",
                stats["n"], stats["first"], stats["last"], src_ip=ip,
            ))
        if stats["users"] >= SPRAY_USERS:
            users = sorted(set(window.values_list("user", flat=True)))[:8]
            hits.append(Hit(
                "password_spray", ip, "high", f"{ip} tried {stats['users']} different accounts",
                f"Failed sign-ins for {', '.join(u for u in users if u)} and others from {ip} on {source.name}.",
                stats["n"], stats["first"], stats["last"], src_ip=ip,
            ))

    for event in successes:
        earlier = LogEvent.objects.filter(
            source=source, category=C.AUTH_FAILURE, src_ip=event.src_ip,
            occurred_at__gte=event.occurred_at - timedelta(hours=1), occurred_at__lte=event.occurred_at,
        ).count()
        if earlier >= COMPROMISE_FAILURES:
            hits.append(Hit(
                "login_after_failures", f"{event.src_ip}:{event.user}", "critical",
                f"{event.user or 'Someone'} signed in from {event.src_ip} after {earlier} failures",
                f"A sign-in as {event.user or 'an account'} from {event.src_ip} on {source.name} succeeded after "
                f"{earlier} failed attempts from the same address in the hour before. Check whether it was really them; "
                "if not, disable the account and change its password.",
                1, event.occurred_at, event.occurred_at, user=event.user, src_ip=event.src_ip,
            ))
    return hits


SINGLE_EVENT_RULES = {
    # action -> (rule, describe(event))
    "admin_group_added": ("admin_added", lambda e: (f"{e.user or 'An account'} was made an administrator", e.message)),
    "account_created": ("account_created", lambda e: (f"New account: {e.user or 'unknown'}", e.message)),
    "logs_cleared": ("logs_cleared", lambda e: ("A security log was cleared", e.message)),
    "logs_deleted": ("logs_cleared", lambda e: ("Log files were deleted", e.message)),
    "sudo_denied": ("sudo_denied", lambda e: (f"{e.user or 'Someone'} tried to use sudo without permission", e.message)),
    "service_installed": ("service_installed", lambda e: ("A new service was installed", e.message)),
    "scheduled_task_created": ("service_installed", lambda e: ("A new scheduled task was created", e.message)),
    "account_locked_out": ("account_locked_out", lambda e: (f"Account locked out: {e.user or 'unknown'}", e.message)),
}


def _single_event_rules(events: list[LogEvent]) -> list[Hit]:
    hits = []
    for event in events:
        if event.action == "ssh_login" and event.user == "root":
            hits.append(Hit(
                "root_login", event.src_ip or "", "high", f"Signed in as root from {event.src_ip or 'unknown address'}",
                event.message, 1, event.occurred_at, event.occurred_at, user="root", src_ip=event.src_ip,
            ))
        rule = SINGLE_EVENT_RULES.get(event.action)
        if rule:
            name, describe = rule
            title, description = describe(event)
            hits.append(Hit(
                name, event.user or event.action, RULE_INFO[name][0], title[:255], description[:2000],
                1, event.occurred_at, event.occurred_at, user=event.user, src_ip=event.src_ip,
            ))
    return hits


def _record(source, hit: Hit) -> LogDetection | None:
    """Merges into a recent open detection of the same kind, or creates one (returned)."""
    existing = LogDetection.objects.filter(
        source=source, rule=hit.rule, key=hit.key, status=LogDetection.Status.OPEN,
        last_seen__gte=hit.last_seen - MERGE_WITHIN,
    ).first()
    if existing:
        # Counting rules report the whole window each time; single events add one.
        existing.event_count = max(existing.event_count, hit.events) if hit.events > 1 else existing.event_count + 1
        existing.last_seen = max(existing.last_seen, hit.last_seen)
        existing.title, existing.description = hit.title, hit.description
        existing.save(update_fields=["event_count", "last_seen", "title", "description"])
        return None
    return LogDetection.objects.create(
        organization_id=source.organization_id, source=source, rule=hit.rule, key=hit.key[:255],
        severity=hit.severity, title=hit.title[:255], description=hit.description, user=hit.user[:128],
        src_ip=hit.src_ip, event_count=hit.events, first_seen=hit.first_seen, last_seen=hit.last_seen,
    )


def check_silent_sources(now=None) -> list[LogDetection]:
    """Flags sources that went quiet; called every few minutes by celery-beat."""
    from django.conf import settings

    from .models import LogSource

    now = now or timezone.now()
    cutoff = now - timedelta(minutes=settings.LOG_SOURCE_SILENT_AFTER_MINUTES)
    created = []
    for source in LogSource.objects.filter(last_seen_at__lt=cutoff, silent_since__isnull=True):
        source.silent_since = now
        source.save(update_fields=["silent_since"])
        minutes = int((now - source.last_seen_at).total_seconds() // 60)
        detection = _record(source, Hit(
            "source_silent", "", "medium", f"{source.name} stopped sending logs",
            f"Nothing has arrived from {source.name} for {minutes} minutes. Check the server is up and its log shipper "
            "is running; until then, nothing happening on it can be seen.",
            0, source.last_seen_at, now,
        ))
        if detection:
            created.append(detection)
    return created
