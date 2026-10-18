"""
Reading application logs, whatever language wrote them:

- Python: the standard logging module (Densight handler, HTTPHandler), structlog
- Node.js: pino, winston, bunyan
- PHP: Monolog (Laravel, Symfony), as sent by the Densight handler or as JSON
- Ruby: the Densight logger (Rails, Sinatra), lograge request lines
- Go: log/slog through the Densight handler, zap and logrus JSON
- Java/Kotlin: Logback with logstash-logback-encoder, Log4j2 JSON/ECS layouts
- .NET: Serilog compact JSON (CLEF), Microsoft.Extensions.Logging JSON console
- anything else that sends JSON with a message (GELF, ECS...)

From each record it takes the level, the message, the logger and
service, an exception and its stack trace, and the request details a
web app logs (method, path, status, client address) -- then decides
what kind of event it is:

- an error (with a fingerprint that groups repeats of the same error);
- a failed sign-in, when a login endpoint answers 401/403 (so the same
  brute-force detection that watches SSH watches the app);
- a web request, flagged when it looks like an attack probe (SQL
  injection, path traversal, a known scanning tool).
"""

import hashlib
import re

from .models import LogEvent

C = LogEvent.Category

TEXT_LEVELS = {
    "trace": "info", "debug": "info", "info": "info", "information": "info", "notice": "info", "http": "info",
    "verbose": "info", "fine": "info", "finer": "info", "finest": "info", "config": "info", "unknown": "info",
    "warn": "warning", "warning": "warning",
    "error": "error", "err": "error", "critical": "error", "crit": "error", "fatal": "error", "alert": "error",
    "emerg": "error", "emergency": "error", "exception": "error", "severe": "error", "panic": "error",
    "dpanic": "error",
}


def numeric_level(value: float) -> str:
    """Each library's numbers: Logback (10000s), Monolog (100s), pino/bunyan (10s), syslog/GELF (0-7)."""
    if value >= 10000:  # Logback level_value: 40000 ERROR, 30000 WARN
        return "error" if value >= 40000 else "warning" if value >= 30000 else "info"
    if value >= 100:  # Monolog: 400 ERROR (and above), 300 WARNING, 250 NOTICE
        return "error" if value >= 400 else "warning" if value >= 300 else "info"
    if value >= 10:  # pino/bunyan: 50 error, 60 fatal, 40 warn
        return "error" if value >= 50 else "warning" if value >= 40 else "info"
    return "error" if value <= 3 else "warning" if value == 4 else "info"  # syslog severity


LOGIN_PATH = re.compile(r"/(?:login|log-in|signin|sign-in|auth|authenticate|token|session|oauth/token)\b", re.I)
ATTACK = re.compile(
    r"(?:\.\./|\.\.%2f|%2e%2e|/etc/passwd|win\.ini|"  # path traversal
    r"union(?:\s|%20|\+)+(?:all(?:\s|%20|\+)+)?select|(?:\s|%20|\+|')or(?:\s|%20|\+)+1=1|sleep\(\d|benchmark\(|"  # SQL injection
    r"<script|%3cscript|javascript:|onerror=|"  # XSS
    r"\$\{jndi:|"  # Log4Shell
    r"/\.env\b|/\.git/|/wp-admin/|/phpmyadmin|/cgi-bin/|\.php\b)",  # common probes
    re.I,
)
SCANNER_AGENTS = re.compile(r"sqlmap|nikto|nuclei|masscan|zgrab|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf", re.I)
PYTHON_FRAME = re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<func>\S+)')
NODE_FRAME = re.compile(r"at (?:(?P<func>[^\s(]+) \()?(?P<file>[^():\s]+):(?P<line>\d+):\d+\)?")
VOLATILE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|\b0x[0-9a-f]+\b|\b[0-9a-f]{16,}\b|"
    r"\b\d+(?:\.\d+)*\b|'[^']*'|\"[^\"]*\"|\S+@\S+",
    re.I,
)


def first(record: dict, *paths):
    """The first non-empty value among dotted paths ("req.method"), also written as one key ("log.level")."""
    for path in paths:
        if record.get(path) not in (None, "", {}, []):
            return record[path]
        value = record
        for part in path.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value not in (None, "", {}, []):
            return value
    return None


CLEF_HOLE = re.compile(r"\{@?\$?([A-Za-z0-9_]+)(?:[,:][^}]*)?\}")


def unwrap(record: dict) -> dict:
    """
    Brings each library's layout to one shape: winston's JSON-RPC wrapper,
    Monolog's "context" and "extra", Serilog's message template.
    """
    if isinstance(record.get("params"), dict) and record.get("method") in ("log", "collect") and len(record) <= 3:
        return record["params"]
    if "channel" in record and ("level_name" in record or "datetime" in record):
        # Monolog: what the code passed is in "context", what processors added in "extra".
        merged = dict(record)
        for nested in ("extra", "context"):
            if isinstance(record.get(nested), dict):
                for key, value in record[nested].items():
                    merged.setdefault(key, value)
        return merged
    if isinstance(record.get("Properties"), dict) and ("MessageTemplate" in record or "RenderedMessage" in record):
        # Serilog's JSON formatter (and Serilog.Sinks.Http): properties nested under "Properties".
        merged = dict(record)
        for key, value in record["Properties"].items():
            merged.setdefault(key, value)
        return merged
    if "@mt" in record and "@m" not in record:
        # Serilog compact JSON without the rendered message: fill the template's holes.
        def fill(match):
            value = record.get(match.group(1))
            return match.group(0) if value is None else str(value)
        return {**record, "@m": CLEF_HOLE.sub(fill, str(record["@mt"]))}
    return record


def level_of(record: dict) -> str:
    value = first(record, "levelname", "level_name", "level", "severity", "log.level", "@l", "LogLevel", "Level",
                  "level_value")
    if isinstance(value, bool):
        return "info"
    if isinstance(value, (int, float)):
        return numeric_level(value)
    text = str(value or "info").strip().lower()
    if text.isdigit():
        return numeric_level(int(text))
    return TEXT_LEVELS.get(text, "info")


STACK_KEYS = ("stacktrace", "stack_trace", "stack", "traceback", "exc_text", "exc_info", "@x", "Exception",
              "exception", "error.stack_trace", "errorVerbose", "backtrace")
LOOKS_LIKE_STACK = re.compile(
    r"Traceback \(most recent|\n\s+at |\n#\d+ |\.rb:\d+:in |\.go:\d+|^goroutine \d+|\.php[:(]\d+|Exception|Error",
    re.M,
)


def exception_of(record: dict) -> tuple[str, str, str]:
    """(type, message, stack trace) of an exception in the record, or empty strings."""
    exc = None
    for key in ("exception", "exc", "err", "error", "@x", "Exception"):
        if isinstance(record.get(key), dict) and record[key]:
            exc = record[key]
            break
    if exc is not None:
        stack = exc.get("stacktrace") or exc.get("stack") or exc.get("traceback") or exc.get("stack_trace") or ""
        kind = str(exc.get("type") or exc.get("name") or exc.get("class") or exc.get("kind") or "")
        value = str(exc.get("value") or exc.get("message") or exc.get("msg") or "")
        if isinstance(stack, list):
            stack = "\n".join(str(line) for line in stack)
        stack = str(stack)
        if exc.get("class") and exc.get("file") and "#0 " not in stack:
            # Monolog's normalized exception: "file" is where it was thrown, "trace" the callers.
            trace = exc.get("trace") or []
            stack = f"{kind}: {value} in {exc['file']}\nStack trace:\n" + "\n".join(
                f"#{i} {_php_location(frame)}" for i, frame in enumerate(trace if isinstance(trace, list) else [])
            )
        if not kind and stack:
            kind, value = _from_stack(stack, value)
        return kind[:200], value, stack
    stack = ""
    for key in STACK_KEYS:
        value = record.get(key)
        if isinstance(value, str) and "\n" in value and LOOKS_LIKE_STACK.search(value):
            stack = value
            break
    if stack:
        kind, value = _from_stack(stack, "")
        if not kind and isinstance(record.get("error"), str):
            value = record["error"]  # zap/logrus: the error text, with the call stack beside it
        return kind[:200], value, stack
    return "", "", ""


def _php_location(frame) -> str:
    """Monolog writes trace frames as "/path/File.php:42"; shown as PHP prints them."""
    match = re.match(r"(.+):(\d+)$", str(frame))
    return f"{match.group(1)}({match.group(2)}): " if match else str(frame)


FIRST_LINE_NOISE = re.compile(r"^(?:PHP )?(?:Fatal error|Uncaught exception)?:?\s*(?:Uncaught\s+)?|^Exception in thread \"[^\"]*\"\s+")


def _from_stack(stack: str, value: str) -> tuple[str, str]:
    lines = [line for line in stack.strip().splitlines() if line.strip()]
    if not lines:
        return "", value
    if lines[0].startswith("Traceback"):
        last = lines[-1]  # Python: "KeyError: 'sku'"
    elif lines[0].startswith("panic: "):
        return "panic", value or lines[0][len("panic: "):]  # Go
    elif lines[0].startswith("goroutine ") or re.match(r"^[\w./*()$-]+$", lines[0]) and len(lines) > 1 \
            and lines[1].startswith("\t"):
        return "", value  # Go call stack (zap): no exception type
    else:
        # Node, Java, .NET, PHP, Ruby: "TypeError: Cannot read properties of undefined"
        last = FIRST_LINE_NOISE.sub("", lines[0])
    kind, _, message = last.partition(":")
    kind = kind.strip()
    if " " in kind or not kind:
        return "Error", value or last.strip()
    message = re.sub(r"\s+in \S+\.php(?::\d+|\(\d+\))\s*$", "", message.strip())  # PHP: "... in /x.php:12"
    return kind, value or message


# Stack frame formats: (pattern, innermost frame comes last, library code).
FRAME_FORMATS = [
    # Python: File "/srv/app/orders/views.py", line 42, in checkout
    (re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<func>\S+)'), True,
     re.compile(r"site-packages|dist-packages|<frozen|/lib/python\d")),
    # Java/Kotlin: at com.acme.orders.CheckoutService.charge(CheckoutService.java:42)
    (re.compile(r"^\s*at (?P<func>[\w$.<>/]+)\((?P<file>[\w$.-]+\.(?:java|kt|scala|groovy))(?::(?P<line>\d+))?\)", re.M),
     False, re.compile(r"^(?:java|javax|jdk|sun|com\.sun|jakarta|org\.springframework|org\.apache|ch\.qos|"
                       r"com\.fasterxml|io\.netty|org\.hibernate|kotlin|kotlinx|reactor|io\.micrometer|org\.eclipse|"
                       r"com\.zaxxer|io\.undertow|org\.glassfish)\.")),
    # .NET: at Acme.Orders.Checkout.Run(Cart cart) in /src/Orders/Checkout.cs:line 42
    (re.compile(r"^\s*at (?P<func>[^\s(]+)\([^)\n]*\)(?: in (?P<file>[^\n]+?):line (?P<line>\d+))?\s*$", re.M),
     False, re.compile(r"^(?:System|Microsoft)\.")),
    # Node: at computeCart (/srv/app/src/cart.js:88:17)
    (re.compile(r"at (?:(?P<func>[^\s(]+) \()?(?P<file>[^():\s]+):(?P<line>\d+):\d+\)?"), False,
     re.compile(r"node_modules|node:internal|^internal/")),
    # PHP: #0 /var/www/app/Http/Controllers/OrderController.php(42): App\Services\Payment->charge()
    (re.compile(r"^#\d+ (?P<file>[^(\n]+\.php)\((?P<line>\d+)\):(?: (?P<func>[^\s(]+))?", re.M), False,
     re.compile(r"/vendor/")),
    # Ruby: /app/app/models/order.rb:42:in `total'  (Ruby 3.4: 'Order#total')
    (re.compile(r"(?P<file>[^\s:'`]+\.rb):(?P<line>\d+):in [`'](?P<func>[^'`]+)'"), False,
     re.compile(r"/gems/|/rubies/|/lib/ruby/|<internal:")),
    # Go: main.(*Server).checkout(...)\n\t/app/internal/orders/handler.go:42 +0x1d
    (re.compile(r"^(?P<func>[\w./*()\[\]$-]+?)(?:\([^\n]*\))?\n\t(?P<file>[^\s:]+\.go):(?P<line>\d+)", re.M), False,
     re.compile(r"^/usr/local/go/src/|/go/pkg/mod/|^runtime[./]|^net/http\.|^/usr/lib/go")),
]
# Folders a deploy puts the project in, trimmed from the front of file paths...
DEPLOY_FOLDERS = {"app", "src", "srv", "code", "project", "workspace", "build", "var", "www", "html", "opt", "usr",
                  "deploy", "current", "release", "dist", "home"}
# ...except an "app" folder that is the framework's own source folder (Laravel, Rails, Symfony).
FRAMEWORK_FOLDERS = {"Http", "Models", "Services", "Console", "Jobs", "Providers", "Exceptions", "Listeners", "Mail",
                     "Policies", "Livewire", "Filament", "Actions", "Events", "Controller", "Entity", "Repository",
                     "controllers", "models", "views", "helpers", "jobs", "mailers", "services", "channels",
                     "workers", "graphql", "lib"}


def project_path(path: str) -> str:
    """/var/www/html/app/Http/Kernel.php -> app/Http/Kernel.php; /srv/app/src/cart.js -> cart.js."""
    parts = path.replace("\\", "/").lstrip("/").split("/")
    while len(parts) > 1 and parts[0] in DEPLOY_FOLDERS:
        if parts[0] == "app" and parts[1] in FRAMEWORK_FOLDERS:
            break
        parts = parts[1:]
    return "/".join(parts)


PHP_THROWN = re.compile(r"^[^\n]*? in (?P<file>\S+\.php)[:(](?P<line>\d+)\)?\s*$", re.M)
PHP_FIRST_FRAME = re.compile(r"^#0 [^\n]*?\): (?P<func>[^\s(]+)", re.M)


def culprit_of(stack: str) -> str:
    """Where it happened: the innermost frame in the app's own code (not libraries)."""
    thrown = PHP_THROWN.search(stack.split("\nStack trace:")[0])
    if thrown and "/vendor/" not in thrown["file"]:
        # PHP names the exact place it was thrown; frame #0 is the function that threw.
        func = PHP_FIRST_FRAME.search(stack)
        file = project_path(thrown["file"])
        return (f"{file} in {func['func']}" if func else file)[:300]
    for pattern, innermost_last, library in FRAME_FORMATS:
        frames = [m.groupdict() for m in pattern.finditer(stack)]
        if not frames:
            continue
        own = [f for f in frames if not library.search(f.get("file") or "") and not library.search(f.get("func") or "")]
        chosen = own or frames
        frame = chosen[-1] if innermost_last else chosen[0]
        file = project_path(frame.get("file") or "")
        func = frame.get("func") or "<anonymous>"
        return (f"{file} in {func}" if file else func)[:300]
    # PHP's own "... in /var/www/app/Foo.php:12" with no trace.
    match = re.search(r" in (\S+\.php)[:(](\d+)", stack)
    return project_path(match.group(1))[:300] if match else ""


def fingerprint(kind: str, culprit: str, message: str, logger: str) -> str:
    """Same error = same type at the same place; without a place, the same message minus numbers and ids."""
    if kind and culprit:
        basis = f"{kind}|{culprit}"
    else:
        basis = f"{kind}|{culprit or logger}|{VOLATILE.sub('?', message)[:200]}"
    return hashlib.sha1(basis.encode()).hexdigest()


def classify(event, record: dict) -> None:
    """Fills the application fields of a Normalized event from the record."""
    event.level = level_of(record)
    service = first(record, "service.name", "service", "app", "application", "name")
    event.service = str(service)[:100] if service is not None and not isinstance(service, (dict, list)) else ""
    release = first(record, "release", "version", "app_version", "service.version", "git_sha", "commit", "sha")
    event.release = str(release)[:100] if release is not None and not isinstance(release, (dict, list)) else ""
    if not event.program:
        logger = first(record, "logger", "logger_name", "channel", "SourceContext", "Category", "progname", "name",
                       "module")
        event.program = str(logger)[:128] if logger is not None and not isinstance(logger, (dict, list)) else ""

    method = first(record, "method", "req.method", "request.method", "http.method", "http.request.method",
                   "request_method", "http_method", "RequestMethod", "httpRequest.requestMethod")
    path = first(record, "path", "url", "req.url", "request.path", "request.url", "http.url", "http.target",
                 "url.path", "uri", "request_uri", "RequestPath", "url.original", "httpRequest.requestUrl")
    status = first(record, "status", "status_code", "statusCode", "res.statusCode", "response.status",
                   "http.status_code", "http.response.status_code", "StatusCode", "response_status",
                   "httpRequest.status")
    ip = first(record, "ip", "client_ip", "remote_addr", "remoteAddress", "req.remoteAddress", "req.ip",
               "request.ip", "http.client_ip", "client.address", "client.ip", "remote_ip", "clientIP",
               "RemoteIpAddress", "httpRequest.remoteIp")
    agent = str(first(record, "user_agent", "userAgent", "req.headers.user-agent", "http.user_agent",
                      "user_agent.original", "UserAgent", "httpRequest.userAgent") or "")
    user = first(record, "user", "username", "user_id", "userId", "user.name", "user.id", "UserName", "UserId")

    from .normalize import _ip

    event.src_ip = _ip(ip) or event.src_ip
    if user and not isinstance(user, (dict, list)):
        event.user = str(user)[:128]
    try:
        event.http_status = int(status) if status is not None else None
    except (TypeError, ValueError):
        event.http_status = None

    kind, value, stack = exception_of(record)
    if kind or event.level == "error":
        culprit = culprit_of(stack) if stack else ""
        event.category, event.action = C.APP_ERROR, "exception" if kind else "error_log"
        event.exception_type = kind
        event.culprit = culprit
        event.stacktrace = stack[:8000]
        if kind and value and value not in event.message:
            event.message = f"{event.message} — {kind}: {value}" if event.message else f"{kind}: {value}"
        # With a type, the error's own text; without one (zap, logrus), the logged message.
        event.fingerprint = fingerprint(kind, culprit, (value if kind else "") or event.message, event.program)
        return

    if method or (path and event.http_status):
        target = f"{method or ''} {path or ''}".strip()
        if not event.message:
            event.message = f"{target} {event.http_status or ''}".strip()
        event.category, event.action = C.HTTP_REQUEST, "http_request"
        if event.http_status and event.http_status >= 500:
            event.level = "error"
        if event.http_status in (401, 403) and path and LOGIN_PATH.search(str(path)):
            # A failed sign-in to the app: counted with SSH and RDP ones.
            event.category, event.action = C.AUTH_FAILURE, "app_login_failed"
            event.level = "warning"
        elif ATTACK.search(f"{path or ''}") or SCANNER_AGENTS.search(agent):
            event.action = "attack_probe"
            event.level = "warning"
