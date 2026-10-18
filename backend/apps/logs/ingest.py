"""
POST /api/ingest/ -- where servers' log shippers send their logs.

Authenticated by the server's own ingest key (not a person's session):

    Authorization: Bearer dsl_...

The body is JSON: an array of records (what Fluent Bit's http output
sends with Format json), a single record, or one record per line
(NDJSON). It may be gzip-compressed (Content-Encoding: gzip). Records
are stored right away and analysed for detections in the background,
so a busy server is never kept waiting.
"""

import json
import logging
import zlib
from urllib.parse import parse_qs

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import F
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import ErrorGroup, LogDetection, LogEvent, LogSource
from .normalize import normalize

logger = logging.getLogger("apps.logs")


class IngestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class StoredBatch(list):
    """The saved events, plus the error groups this batch created or brought back."""

    new_groups: list
    regressed_groups: list


def store(source: LogSource, records: list) -> StoredBatch:
    """Normalizes and saves records for a source; returns the saved events."""
    app = source.is_application
    events, normalized = [], []
    for record in records:
        n = normalize(record, app=app)
        normalized.append(n)
        events.append(LogEvent(
            organization_id=source.organization_id, source=source, occurred_at=n.occurred_at, host=n.host[:255],
            program=n.program[:128], event_id=n.event_id, level=n.level, category=n.category, action=n.action,
            user=n.user, src_ip=n.src_ip, message=n.message, raw=n.raw, service=n.service,
            http_status=n.http_status, fingerprint=n.fingerprint, redacted=n.redacted, release=n.release[:100],
        ))
    batch = StoredBatch()
    batch.new_groups, batch.regressed_groups = [], []
    if not events:
        return batch
    with transaction.atomic():
        saved = LogEvent.objects.bulk_create(events, batch_size=1000)
        LogSource.objects.filter(id=source.id).update(
            events_received=F("events_received") + len(saved),
            last_seen_at=timezone.now(),
            last_host=next((e.host for e in reversed(saved) if e.host), source.last_host)[:255],
            silent_since=None,
        )
        if source.silent_since is not None:
            # It is talking again: the outage detection is over.
            LogDetection.objects.filter(source=source, rule="source_silent", status=LogDetection.Status.OPEN).update(
                status=LogDetection.Status.RESOLVED, resolved_at=timezone.now()
            )
        if app:
            batch.new_groups, batch.regressed_groups = _group_errors(source, normalized)
    batch.extend(saved)
    return batch


def _group_errors(source: LogSource, normalized) -> tuple[list, list]:
    """Adds this batch's errors to their groups; returns (new groups, groups that came back after being resolved)."""
    by_fingerprint: dict = {}
    for n in normalized:
        if n.fingerprint:
            by_fingerprint.setdefault(n.fingerprint, []).append(n)
    new, regressed = [], []
    for fingerprint, occurrences in by_fingerprint.items():
        latest = max(occurrences, key=lambda n: n.occurred_at)
        earliest = min(n.occurred_at for n in occurrences)
        title = (latest.message or latest.exception_type or "Error")[:500]
        group = ErrorGroup.objects.select_for_update().filter(source=source, fingerprint=fingerprint).first()
        if group is None:
            group = ErrorGroup.objects.create(
                organization_id=source.organization_id, source=source, fingerprint=fingerprint,
                exception_type=latest.exception_type, title=title, culprit=latest.culprit, service=latest.service,
                count=len(occurrences), first_seen=earliest, last_seen=latest.occurred_at,
                stacktrace=latest.stacktrace,
                first_release=min(occurrences, key=lambda n: n.occurred_at).release or latest.release,
                last_release=latest.release,
            )
            new.append(group)
            continue
        group.count += len(occurrences)
        group.last_seen = max(group.last_seen, latest.occurred_at)
        group.title = title
        if latest.stacktrace:
            group.stacktrace = latest.stacktrace
        if latest.release:
            group.last_release = latest.release
            group.first_release = group.first_release or latest.release
        if group.status == ErrorGroup.Status.RESOLVED:
            group.status, group.resolved_at = ErrorGroup.Status.UNRESOLVED, None
            group.regressions += 1
            regressed.append(group)
        group.save()
    return new, regressed


def _authenticate(request) -> LogSource:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        key = header[7:].strip()
    elif header.lower().startswith("basic "):
        # logging.handlers.HTTPHandler can only send Basic credentials: the key is the password.
        import base64

        try:
            key = base64.b64decode(header[6:].strip()).decode().partition(":")[2]
        except (ValueError, UnicodeDecodeError):
            key = ""
    else:
        key = request.headers.get("X-Densight-Key", "").strip()
    if not key.startswith(LogSource.PREFIX):
        raise IngestError(401, "Send the server's ingest key as 'Authorization: Bearer dsl_...'.")
    source = LogSource.objects.select_related("organization").filter(key_hash=LogSource.hash_key(key)).first()
    if source is None:
        raise IngestError(401, "Unknown or replaced ingest key.")
    if not source.organization.is_active:
        raise IngestError(403, "This organization is not active.")
    return source


def _throttle(source: LogSource) -> None:
    bucket = f"log-ingest:{source.id}:{timezone.now().strftime('%Y%m%d%H%M')}"
    cache.add(bucket, 0, timeout=120)
    if cache.incr(bucket) > settings.LOG_INGEST_MAX_REQUESTS_PER_MINUTE:
        raise IngestError(429, "Too many requests from this server; send larger batches less often.")


def _read_body(request) -> bytes:
    limit = settings.LOG_INGEST_MAX_BYTES
    length = request.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > limit:
        raise IngestError(413, f"Batches are limited to {limit // 1_000_000} MB.")
    body = request.read(limit + 1)
    if len(body) > limit:
        raise IngestError(413, f"Batches are limited to {limit // 1_000_000} MB.")
    if request.headers.get("Content-Encoding", "").lower() == "gzip" or body[:2] == b"\x1f\x8b":
        # Bounded, so a small compressed bomb can't expand into gigabytes.
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            body = inflater.decompress(body, limit * 4)
        except zlib.error:
            raise IngestError(400, "The body says it is gzip but isn't.")
        if inflater.unconsumed_tail:
            raise IngestError(413, "The batch is too large once uncompressed.")
    return body


def _parse(body: bytes, content_type: str = "") -> list:
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    if "application/x-www-form-urlencoded" in content_type:
        # Python's logging.handlers.HTTPHandler posts the record's fields as a form.
        return [{key: values[-1] for key, values in parse_qs(text, keep_blank_values=True).items()}]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError:
            raise IngestError(400, "The body must be JSON: an array of records, one record, or one record per line.")
    records = data if isinstance(data, list) else [data]
    if len(records) > settings.LOG_INGEST_MAX_RECORDS:
        raise IngestError(413, f"At most {settings.LOG_INGEST_MAX_RECORDS} records per batch.")
    return records


@csrf_exempt
@require_POST
def ingest(request):
    try:
        source = _authenticate(request)
        _throttle(source)
        records = _parse(_read_body(request), request.headers.get("Content-Type", ""))
    except IngestError as error:
        return JsonResponse({"detail": error.message}, status=error.status)

    events = store(source, records)
    if events:
        from .tasks import analyze_events

        analyze_events.delay(
            str(source.id), events[0].id, events[-1].id,
            [str(g.id) for g in events.new_groups], [str(g.id) for g in events.regressed_groups],
        )
    return JsonResponse({"accepted": len(events)}, status=202)

