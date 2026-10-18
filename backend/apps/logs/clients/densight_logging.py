"""
Send a Python application's logs to Densight.

Standard library only: copy this file into your project, then

    import logging
    from densight_logging import DensightHandler

    logging.getLogger().addHandler(DensightHandler(
        url="https://densight.example.com/api/ingest/",
        key="dsl_...",                # the application's ingest key
        service="orders-api",
    ))

Django: add it to LOGGING (see the Densight setup page). Records are
queued and sent in batches from a background thread, so logging never
slows a request, and a Densight outage never breaks the application.
Pass release="2.15.0" (or set DENSIGHT_RELEASE) to name the version or
commit running, so Densight can tell which deploy introduced an error.
Exceptions logged with logger.exception(...) or exc_info=True are sent
with their stack trace, and grouped into errors in Densight. Extra
fields (logger.info("...", extra={"user": ..., "ip": ...,
"status": ..., "path": ...})) are sent along.
"""

import atexit
import json
import logging
import os
import queue
import socket
import threading
import time
import traceback
import urllib.request

_STANDARD = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class DensightHandler(logging.Handler):
    def __init__(self, url: str, key: str, service: str = "", environment: str = "", release: str = "",
                 batch_size: int = 200, flush_interval: float = 2.0, level=logging.INFO):
        super().__init__(level)
        self.url, self.key = url, key
        self.service, self.environment = service, environment
        # Not "self.release": logging.Handler.release() releases its lock.
        self.app_release = release or os.environ.get("DENSIGHT_RELEASE", "")
        self.batch_size, self.flush_interval = batch_size, flush_interval
        self.host = socket.gethostname()
        self._start_sender()
        atexit.register(self.flush)

    def _start_sender(self) -> None:
        self._pid = os.getpid()
        self._queue: queue.Queue = queue.Queue(maxsize=20000)
        self._thread = threading.Thread(target=self._run, name="densight-logging", daemon=True)
        self._thread.start()

    def emit(self, record: logging.LogRecord) -> None:
        if self._pid != os.getpid():
            # A forked child (Celery's prefork pool, gunicorn --preload, multiprocessing):
            # threads don't survive fork, so start this process's own sender. emit() runs
            # under the handler's lock, so only one thread gets here.
            self._start_sender()
        try:
            entry = {
                "timestamp": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "service": self.service,
                "environment": self.environment,
                "release": self.app_release,
                "host": self.host,
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }
            if record.exc_info and record.exc_info[0] is not None:
                entry["exception"] = {
                    "type": record.exc_info[0].__name__,
                    "value": str(record.exc_info[1]),
                    "stacktrace": "".join(traceback.format_exception(*record.exc_info)),
                }
            for key, value in vars(record).items():
                if key not in _STANDARD and not key.startswith("_"):
                    entry[key] = value
            self._queue.put_nowait(entry)
        except queue.Full:
            pass  # never block or crash the application over logging
        except Exception:
            self.handleError(record)

    def flush(self) -> None:
        self._send(self._drain(10_000))

    def _run(self) -> None:
        while True:
            batch = [self._queue.get()]
            deadline = time.monotonic() + self.flush_interval
            while len(batch) < self.batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(self._queue.get(timeout=remaining))
                except queue.Empty:
                    break
            self._send(batch)

    def _drain(self, limit: int) -> list:
        items = []
        while len(items) < limit:
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items

    def _send(self, batch: list) -> None:
        if not batch:
            return
        request = urllib.request.Request(
            self.url, data=json.dumps(batch, default=str).encode("utf-8"), method="POST",
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(request, timeout=10).close()
        except Exception:
            pass  # dropped: an unreachable Densight must not affect the application
