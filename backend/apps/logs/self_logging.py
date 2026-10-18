"""
Densight sending its own logs to itself (see DENSIGHT_LOG_KEY in
settings).

The one thing to watch is a feedback loop: every batch the handler
sends is a request to /api/ingest/, which queues an analyze_events
task, and each of those logs something -- which would be sent as the
next batch, and so on forever. This filter drops the log pipeline's own
records before they reach the handler.
"""

import logging

# Loggers whose records are about receiving or analysing logs.
PIPELINE_LOGGERS = ("apps.logs", "django.server")
PIPELINE_MARKERS = ("/api/ingest/", "apps.logs.tasks")


class SkipLogPipeline(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name.startswith(PIPELINE_LOGGERS):
            return False
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a malformed record is simply not sent
            return False
        return not any(marker in message for marker in PIPELINE_MARKERS)
