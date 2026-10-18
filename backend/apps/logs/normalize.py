"""
Turning what a log shipper sends into LogEvent fields.

Three shapes are understood, so the same search and detections work
whatever the server runs:

- Linux through Fluent Bit's systemd input (journald): MESSAGE,
  SYSLOG_IDENTIFIER, PRIORITY, _HOSTNAME, and Fluent Bit's "date".
- Linux through a tailed syslog file: either already split (ident,
  message, host, time) or a raw line ("Oct 17 10:00:01 web-01 sshd[812]: ...").
- Windows through Fluent Bit's winevtlog/winlog input: EventID, Channel,
  Computer, Message, TimeCreated, StringInserts.

Anything else is accepted as a generic event: {"timestamp", "host",
"program", "message", "level"}.

Then the message is read for what security people care about: who
signed in or failed to, from which address, who got admin rights,
whether logs were cleared.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone as dt_timezone

from django.utils import timezone

from . import app_logs
from .models import LogEvent
from .redact import redact_value

C = LogEvent.Category
MESSAGE_MAX = 4000
RAW_MAX_KEYS = 40
ADMIN_GROUPS = {"sudo", "wheel", "admin", "administrators", "domain admins", "enterprise admins"}


@dataclass
class Normalized:
    occurred_at: datetime
    host: str = ""
    program: str = ""
    event_id: int | None = None
    level: str = LogEvent.Level.INFO
    category: str = C.OTHER
    action: str = ""
    user: str = ""
    src_ip: str | None = None
    message: str = ""
    raw: dict = field(default_factory=dict)
    # Applications (see app_logs.py).
    service: str = ""
    http_status: int | None = None
    fingerprint: str = ""
    exception_type: str = ""
    culprit: str = ""
    stacktrace: str = ""
    # The application version or commit that logged it.
    release: str = ""
    # Kinds of secret masked out (see redact.py).
    redacted: list = field(default_factory=list)


def normalize(record: dict, app: bool = False) -> Normalized:
    """`app`: the record comes from an application (Python, Node...), not a server's system logs."""
    if not isinstance(record, dict):
        record = {"message": str(record)}
    found: set[str] = set()
    # Secrets are masked before anything else looks at the record.
    record = redact_value(record, found)
    if app:
        record = app_logs.unwrap(record)
        event = _generic(record)
        app_logs.classify(event, record)
    elif _first(record, "EventID", "EventId", "event_id") is not None and _first(record, "Channel", "channel"):
        event = _windows(record)
    elif _first(record, "MESSAGE", "SYSLOG_IDENTIFIER", "_HOSTNAME", "HOSTNAME") is not None:
        event = _journald(record)
    elif "log" in record and isinstance(record["log"], str) and len(record) <= 3:
        event = _syslog_line(record["log"], record)
    else:
        event = _generic(record)
    event.message = event.message[:MESSAGE_MAX]
    event.raw = _trim(record)
    if not app:
        if event.event_id is not None:
            _classify_windows(event, record)
        else:
            _classify_linux(event)
    event.redacted = sorted(found)
    return event


# ---------------------------------------------------------------- shapes

def _journald(r: dict) -> Normalized:
    priority = _int(_first(r, "PRIORITY", "priority"))
    return Normalized(
        occurred_at=_time(_first(r, "date", "__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP", "time")),
        host=str(_first(r, "_HOSTNAME", "HOSTNAME", "host") or ""),
        program=str(_first(r, "SYSLOG_IDENTIFIER", "_COMM", "COMM") or ""),
        level=_syslog_level(priority),
        message=str(_first(r, "MESSAGE", "message") or ""),
    )


SYSLOG_LINE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?P<ts>[A-Z][a-z]{2}\s+\d+\s[\d:]{8}|\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-][\d:]+)?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s:\[]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)


def _syslog_line(line: str, r: dict) -> Normalized:
    match = SYSLOG_LINE.match(line.strip())
    if not match:
        return Normalized(occurred_at=_time(_first(r, "date", "time")), message=line)
    pri = _int(match["pri"])
    return Normalized(
        occurred_at=_time(match["ts"]) if "T" in match["ts"] else _time(_first(r, "date")),
        host=match["host"],
        program=match["prog"],
        level=_syslog_level(pri % 8 if pri is not None else None),
        message=match["msg"],
    )


def _generic(r: dict) -> Normalized:
    level = str(_first(r, "level", "severity") or "").lower()
    host = _first(r, "host", "hostname", "MachineName", "HOSTNAME")
    program = _first(r, "program", "ident", "logger", "source")
    return Normalized(
        # "date" last: Fluent Bit adds it as the time it read the line, not when it was written.
        occurred_at=_time(_first(r, "timestamp", "time", "@timestamp", "@t", "datetime", "ts", "Timestamp", "created",
                                 "asctime", "date")),
        host=str(host)[:255] if host is not None and not isinstance(host, (dict, list)) else "",
        program=str(program) if program is not None and not isinstance(program, (dict, list)) else "",
        level=(LogEvent.Level.ERROR if level in ("error", "err", "critical", "crit", "alert", "emerg")
               else LogEvent.Level.WARNING if level in ("warning", "warn", "notice") else LogEvent.Level.INFO),
        message=str(_first(r, "message", "msg", "@m", "Message", "RenderedMessage", "short_message", "event", "log")
                    or ""),
    )


WINDOWS_LEVEL = {1: LogEvent.Level.ERROR, 2: LogEvent.Level.ERROR, 3: LogEvent.Level.WARNING}


def _windows(r: dict) -> Normalized:
    level = _first(r, "Level", "EventType")
    if isinstance(level, str):
        lowered = level.lower()
        level_value = (LogEvent.Level.ERROR if "error" in lowered or "critical" in lowered or "failure" in lowered
                       else LogEvent.Level.WARNING if "warn" in lowered else LogEvent.Level.INFO)
    else:
        level_value = WINDOWS_LEVEL.get(_int(level), LogEvent.Level.INFO)
    return Normalized(
        occurred_at=_time(_first(r, "TimeCreated", "TimeGenerated", "date")),
        host=str(_first(r, "Computer", "ComputerName") or ""),
        program=str(_first(r, "Channel", "channel") or ""),
        event_id=_int(_first(r, "EventID", "EventId", "event_id")),
        level=level_value,
        message=str(_first(r, "Message", "message") or ""),
    )


# ---------------------------------------------------------------- reading the message

LINUX_PATTERNS = [
    # (program prefix or None, regex, category, action)
    ("sshd", re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)"),
     C.AUTH_FAILURE, "ssh_failed_login"),
    ("sshd", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\da-fA-F.:]+)"), C.AUTH_FAILURE, "ssh_invalid_user"),
    ("sshd", re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)"),
     C.AUTH_SUCCESS, "ssh_login"),
    (None, re.compile(r"authentication failure;.*?(?:rhost=(?P<ip>[\da-fA-F.:]+))?\s*(?:user=(?P<user>\S+))?$"),
     C.AUTH_FAILURE, "pam_auth_failure"),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : .*user NOT in sudoers"), C.PRIVILEGE, "sudo_denied"),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$"), C.PRIVILEGE, "sudo_command"),
    ("su", re.compile(r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+)"), C.AUTH_FAILURE, "su_failed"),
    ("useradd", re.compile(r"new user: name=(?P<user>[^,\s]+)"), C.ACCOUNT_CHANGE, "account_created"),
    ("userdel", re.compile(r"delete user '(?P<user>[^']+)'"), C.ACCOUNT_CHANGE, "account_deleted"),
    (None, re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"), C.ACCOUNT_CHANGE, "group_member_added"),
    ("passwd", re.compile(r"password changed for (?P<user>\S+)"), C.ACCOUNT_CHANGE, "password_changed"),
]
# Commands that destroy logs, wherever they show up (sudo, shell history, auditd).
LOG_WIPE = re.compile(
    r"(rm\s+(-\w+\s+)*/var/log|truncate\s+.*?/var/log|>\s*/var/log/|journalctl\s+.*--vacuum|shred\s+.*?/var/log|history\s+-c)"
)


def _classify_linux(event: Normalized) -> None:
    program = event.program.lower()
    for prefix, pattern, category, action in LINUX_PATTERNS:
        if prefix and not program.startswith(prefix):
            continue
        match = pattern.search(event.message)
        if not match:
            continue
        groups = match.groupdict()
        event.category, event.action = category, action
        event.user = (groups.get("user") or "")[:128]
        event.src_ip = _ip(groups.get("ip"))
        if action == "group_member_added" and (groups.get("group") or "").lower() in ADMIN_GROUPS:
            event.category, event.action = C.PRIVILEGE, "admin_group_added"
        if action == "sudo_command" and LOG_WIPE.search(groups.get("cmd") or ""):
            event.category, event.action = C.LOG_TAMPERING, "logs_deleted"
        if category == C.AUTH_FAILURE and event.level == LogEvent.Level.INFO:
            event.level = LogEvent.Level.WARNING
        return
    if LOG_WIPE.search(event.message):
        event.category, event.action = C.LOG_TAMPERING, "logs_deleted"


# Windows Security / System event ids that matter, and where the user and
# address sit in StringInserts (the event's data fields, in order).
WINDOWS_EVENTS = {
    4624: (C.AUTH_SUCCESS, "windows_logon", 5, 18),
    4625: (C.AUTH_FAILURE, "windows_logon_failed", 5, 19),
    4648: (C.AUTH_SUCCESS, "windows_explicit_logon", 5, 12),
    4672: (C.PRIVILEGE, "windows_special_privileges", 1, None),
    4720: (C.ACCOUNT_CHANGE, "account_created", 0, None),
    4722: (C.ACCOUNT_CHANGE, "account_enabled", 0, None),
    4724: (C.ACCOUNT_CHANGE, "password_reset", 0, None),
    4726: (C.ACCOUNT_CHANGE, "account_deleted", 0, None),
    4728: (C.ACCOUNT_CHANGE, "group_member_added", 0, None),
    4732: (C.ACCOUNT_CHANGE, "group_member_added", 0, None),
    4756: (C.ACCOUNT_CHANGE, "group_member_added", 0, None),
    4740: (C.AUTH_FAILURE, "account_locked_out", 0, None),
    1102: (C.LOG_TAMPERING, "logs_cleared", 1, None),
    104: (C.LOG_TAMPERING, "logs_cleared", None, None),
    7045: (C.SERVICE, "service_installed", None, None),
    4697: (C.SERVICE, "service_installed", None, None),
    4698: (C.SERVICE, "scheduled_task_created", 1, None),
}
# A readable line for events that arrive without their message text
# (Windows only renders it when the message file is available).
WINDOWS_DESCRIPTIONS = {
    4624: "An account signed in", 4625: "An account failed to sign in", 4648: "A sign-in with explicit credentials",
    4672: "Admin privileges given to a new sign-in", 4720: "A user account was created",
    4722: "A user account was enabled", 4724: "A password was reset", 4726: "A user account was deleted",
    4728: "A member was added to a global security group", 4732: "A member was added to a local security group",
    4756: "A member was added to a universal security group", 4740: "A user account was locked out",
    1102: "The security log was cleared", 104: "An event log was cleared", 7045: "A service was installed",
    4697: "A service was installed", 4698: "A scheduled task was created",
}
GROUP_NAME_INDEX = {4728: 2, 4732: 2, 4756: 2}
LOGON_TYPE_INDEX = {4624: 8, 4625: 10}
MESSAGE_FIELDS = {
    "user": re.compile(r"Account Name:\s+(?!-\s)(\S[^\r\n]*?)\s*$", re.MULTILINE),
    "ip": re.compile(r"Source Network Address:\s+([\da-fA-F.:]+)"),
    "group": re.compile(r"Group:\s+Security ID:.*?\n\s*(?:Group|Account) Name:\s+([^\r\n]+)", re.DOTALL),
}


def _classify_windows(event: Normalized, record: dict) -> None:
    known = WINDOWS_EVENTS.get(event.event_id)
    if not known:
        return
    category, action, user_index, ip_index = known
    if event.event_id == 104 and "system" not in event.program.lower():
        return  # 104 is "log cleared" only in the System log
    inserts = _inserts(record)
    event.category, event.action = category, action

    user = _at(inserts, user_index)
    if not user or user == "-":
        names = MESSAGE_FIELDS["user"].findall(event.message)
        # The last "Account Name" is the one acted on (the first is who did it).
        user = names[-1] if names else ""
    event.user = user[:128]
    event.src_ip = _ip(_at(inserts, ip_index)) or _ip(_first_match(MESSAGE_FIELDS["ip"], event.message))

    if event.event_id in LOGON_TYPE_INDEX and _at(inserts, LOGON_TYPE_INDEX[event.event_id]) == "10":
        event.action += "_rdp"
    if event.event_id in GROUP_NAME_INDEX:
        group = _at(inserts, GROUP_NAME_INDEX[event.event_id]) or _first_match(MESSAGE_FIELDS["group"], event.message)
        if (group or "").strip().lower() in ADMIN_GROUPS:
            event.category, event.action = C.PRIVILEGE, "admin_group_added"
        member = _at(inserts, 0)
        # The member is often only given as a SID; fall back to who did it.
        if member and member != "-":
            event.user = member[:128]
    if category == C.AUTH_FAILURE and event.level == LogEvent.Level.INFO:
        event.level = LogEvent.Level.WARNING
    if not event.message.strip():
        details = " ".join(part for part in (event.user, f"from {event.src_ip}" if event.src_ip else "") if part)
        event.message = WINDOWS_DESCRIPTIONS[event.event_id] + (f": {details}" if details else "")


# ---------------------------------------------------------------- helpers

def _first(record: dict, *keys):
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _syslog_level(priority: int | None) -> str:
    if priority is None:
        return LogEvent.Level.INFO
    if priority <= 3:
        return LogEvent.Level.ERROR
    if priority == 4:
        return LogEvent.Level.WARNING
    return LogEvent.Level.INFO


def _time(value) -> datetime:
    """Epoch seconds, epoch microseconds, ISO 8601 or "Oct 17 10:00:01"; now if unreadable."""
    now = timezone.now()
    if value is None:
        return now
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d+(\.\d+)?", value)):
        number = float(value)
        if number > 1e14:  # journald's microseconds
            number /= 1e6
        elif number > 1e11:  # milliseconds
            number /= 1e3
        try:
            parsed = datetime.fromtimestamp(number, tz=dt_timezone.utc)
        except (OverflowError, OSError, ValueError):
            return now
    else:
        text = str(value).strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = datetime.strptime(f"{now.year} {text}", "%Y %b %d %H:%M:%S")
            except ValueError:
                return now
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt_timezone.utc)
    # A clock far in the future would sort the event above everything else.
    return min(parsed, now + timezone.timedelta(minutes=5))


def _ip(value) -> str | None:
    if not value:
        return None
    text = str(value).strip().removeprefix("::ffff:")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _inserts(record: dict) -> list[str]:
    inserts = record.get("StringInserts")
    if isinstance(inserts, list):
        return [str(item) for item in inserts]
    return []


def _at(items: list[str], index: int | None) -> str:
    if index is None or index >= len(items):
        return ""
    return items[index].strip()


def _first_match(pattern: re.Pattern, text: str) -> str:
    match = pattern.search(text or "")
    return match.group(1).strip() if match else ""


def _trim(record: dict) -> dict:
    trimmed = {}
    for key in list(record)[:RAW_MAX_KEYS]:
        value = record[key]
        if isinstance(value, str) and len(value) > 1000:
            value = value[:1000] + "…"
        elif isinstance(value, (list, dict)) and len(str(value)) > 2000:
            value = str(value)[:2000] + "…"
        trimmed[str(key)[:64]] = value
    return trimmed
