"""
Minimal JSON log formatter -- no extra dependency (python-json-logger
etc.) needed for this, it's about 20 lines of stdlib logging.Formatter
subclassing. Every log line becomes one JSON object per line, which is
what log aggregators (CloudWatch, Datadog, ELK, Loki, ...) expect --
this is the difference between "logs a human tails in a terminal" and
"logs a system can actually query and alert on."
"""

import json
import logging
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    # Standard LogRecord attributes -- anything NOT in this set that
    # shows up on a record was passed via logger.info(..., extra={...})
    # and should be included as a structured field in the output.
    _RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()) | {"message"}

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key not in self._RESERVED:
                payload[key] = value

        return json.dumps(payload, default=str)