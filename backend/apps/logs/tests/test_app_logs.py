"""
Application logs: what Python and Node.js apps send, secret masking,
error grouping, the app detections, and the real Python handler talking
to a running server.
"""

import base64
import json
import logging
import time
from unittest.mock import patch
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import LiveServerTestCase, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.logs import detections
from apps.logs.detections import analyze
from apps.logs.ingest import store
from apps.logs.models import ErrorGroup, LogDetection, LogEvent, LogSource
from apps.logs.normalize import normalize
from apps.logs.redact import redact_text
from apps.organizations.models import Membership, Organization

JSON = "application/json"
PY_TRACE = (
    "Traceback (most recent call last):\n"
    '  File "/usr/lib/python3.12/site-packages/django/core/handlers/base.py", line 197, in _get_response\n'
    "    response = wrapped_callback(request, *callback_args, **callback_kwargs)\n"
    '  File "/app/orders/views.py", line 42, in checkout\n'
    "    price = prices[sku]\n"
    "KeyError: 'SKU-1042'\n"
)
NODE_STACK = (
    "TypeError: Cannot read properties of undefined (reading 'total')\n"
    "    at computeCart (/srv/app/src/cart.js:88:17)\n"
    "    at Layer.handle (/srv/app/node_modules/express/lib/router/layer.js:95:5)\n"
)


def python_error(sku="SKU-1042", line=42, function="checkout"):
    trace = PY_TRACE.replace("line 42", f"line {line}").replace("in checkout", f"in {function}")
    return {"timestamp": time.time(), "level": "ERROR", "logger": "orders", "message": "Checkout failed",
            "service": "orders-api", "exception": {"type": "KeyError", "value": f"'{sku}'", "stacktrace": trace}}


class AppParsingTests(SimpleTestCase):
    def test_python_handler_exception_is_an_error_with_a_fingerprint(self):
        event = normalize(python_error(), app=True)
        self.assertEqual((event.category, event.action, event.level), ("app_error", "exception", "error"))
        self.assertEqual((event.exception_type, event.culprit, event.service), ("KeyError", "orders/views.py in checkout", "orders-api"))
        self.assertIn("KeyError: 'SKU-1042'", event.message)
        # Same error with a different value, or a few lines further down after an edit: same group.
        # The same exception in another function: a different error.
        self.assertEqual(event.fingerprint, normalize(python_error(sku="SKU-9", line=47), app=True).fingerprint)
        self.assertNotEqual(event.fingerprint, normalize(python_error(function="refund"), app=True).fingerprint)

    def test_pino_error_and_http_requests(self):
        event = normalize({"level": 50, "time": 1760000000000, "pid": 7, "hostname": "api-1", "name": "shop-api",
                           "msg": "unhandled", "err": {"type": "TypeError", "message": "boom", "stack": NODE_STACK}},
                          app=True)
        self.assertEqual((event.level, event.exception_type, event.culprit), ("error", "TypeError", "cart.js in computeCart"))
        self.assertEqual((event.service, event.host, event.occurred_at.year), ("shop-api", "api-1", 2025))
        request = normalize({"level": 30, "msg": "request completed", "req": {"method": "GET", "url": "/cart",
                             "remoteAddress": "::ffff:203.0.113.5"}, "res": {"statusCode": 502}, "responseTime": 31},
                            app=True)
        self.assertEqual((request.category, request.http_status, request.src_ip, request.level),
                         ("http_request", 502, "203.0.113.5", "error"))

    def test_winston_json_rpc_and_stack_strings(self):
        event = normalize({"method": "log", "params": {"level": "error", "message": "Cannot read properties",
                                                       "stack": NODE_STACK, "service": "web"}}, app=True)
        self.assertEqual((event.exception_type, event.service, event.category), ("TypeError", "web", "app_error"))
        info = normalize({"level": "info", "message": "user signed in", "user": "amina"}, app=True)
        self.assertEqual((info.category, info.user, info.level), ("other", "amina", "info"))

    def test_login_failures_and_attack_probes(self):
        failed = normalize({"method": "POST", "path": "/api/auth/login", "status": 401, "ip": "198.51.100.4"}, app=True)
        self.assertEqual((failed.category, failed.action, failed.src_ip), ("auth_failure", "app_login_failed", "198.51.100.4"))
        for path in ["/products?id=1%20UNION%20SELECT%20password", "/../../etc/passwd", "/.env", "/x?q=${jndi:ldap://e}"]:
            with self.subTest(path=path):
                self.assertEqual(normalize({"method": "GET", "path": path, "status": 404}, app=True).action, "attack_probe")
        scanner = normalize({"method": "GET", "path": "/", "status": 200, "user_agent": "sqlmap/1.7"}, app=True)
        self.assertEqual(scanner.action, "attack_probe")
        self.assertEqual(normalize({"method": "GET", "path": "/products/12", "status": 200}, app=True).action, "http_request")


class RedactionTests(SimpleTestCase):
    def test_secrets_are_masked_and_named(self):
        found = set()
        text = redact_text(
            "login password=hunter2 key AKIAIOSFODNN7EXAMPLE auth Bearer abcdefghijklmnop123 "
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U "
            "card 4111 1111 1111 1111 order 1234567890123", found)
        for secret in ("hunter2", "AKIAIOSFODNN7EXAMPLE", "abcdefghijklmnop123", "eyJhbGciOiJIUzI1NiJ9", "4111 1111"):
            self.assertNotIn(secret, text)
        self.assertIn("password=[REDACTED:secret]", text)
        self.assertIn("order 1234567890123", text)  # not a valid card number
        self.assertEqual(found, {"secret", "aws_key", "bearer_token", "jwt", "card_number"})

    def test_whole_records_are_masked_by_key_and_pattern(self):
        event = normalize({"message": "signup", "password": "s3cret!", "headers": {"Authorization": "Basic xyz"},
                           "note": "token: abc123def456"}, app=True)
        self.assertEqual(event.raw["password"], "[REDACTED]")
        self.assertEqual(event.raw["headers"]["Authorization"], "[REDACTED]")
        self.assertNotIn("abc123def456", json.dumps(event.raw))
        self.assertTrue({"password", "secret"} <= set(event.redacted))


class AppFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Acme", root_domain="acme.com")
        cls.users = {}
        for role in Membership.Role.values:
            cls.users[role] = User.objects.create_user(role, password="pass12345!")
            Membership.objects.create(user=cls.users[role], organization=cls.org, role=role)

    def setUp(self):
        cache.clear()
        self.app = LogSource(organization=self.org, name="orders-api", os=LogSource.OS.PYTHON)
        self.key = self.app.issue_key()
        self.app.save()

    def ingest(self, records):
        return analyze(self.app, store(self.app, records))


class ErrorGroupingTests(AppFixture):
    def test_repeats_group_new_errors_alert_and_resolved_ones_come_back(self):
        new = self.ingest([python_error(), python_error(sku="SKU-7"), python_error(function="refund")])
        self.assertEqual(ErrorGroup.objects.count(), 2)
        group = ErrorGroup.objects.get(culprit="orders/views.py in checkout", count=2)
        self.assertEqual((group.exception_type, group.service), ("KeyError", "orders-api"))
        self.assertIn("orders/views.py", group.stacktrace)
        self.assertEqual(sorted(d.rule for d in new), ["new_error", "new_error"])
        # Again: counted, no new alert.
        self.assertEqual(self.ingest([python_error()]), [])
        group.refresh_from_db()
        self.assertEqual(group.count, 3)
        # Resolved, then seen again: it came back.
        ErrorGroup.objects.filter(id=group.id).update(status="resolved")
        back = self.ingest([python_error()])
        self.assertEqual([d.rule for d in back], ["error_regressed"])
        group.refresh_from_db()
        self.assertEqual((group.status, group.regressions), ("unresolved", 1))

    def test_a_flood_of_new_errors_is_one_alert(self):
        records = [{**python_error(), "exception": {"type": f"Error{i}", "value": "x", "stacktrace": ""}}
                   for i in range(8)]
        new = self.ingest(records)
        self.assertEqual([d.title for d in new], ["8 new errors in orders-api"])

    def test_spikes_probes_secrets_and_app_brute_force(self):
        with patch.object(detections, "ERROR_SPIKE", 5), patch.object(detections, "SERVER_ERROR_SPIKE", 5):
            rules = {d.rule for d in self.ingest(
                [{"level": "error", "message": f"db timeout {i}"} for i in range(5)]
                + [{"method": "GET", "path": "/cart", "status": 503, "ip": "10.0.0.1"} for _ in range(5)]
                + [{"method": "GET", "path": f"/x?id=1 UNION SELECT {i}", "status": 404, "ip": "203.0.113.66"}
                   for i in range(5)]
                + [{"method": "POST", "path": "/login", "status": 401, "ip": "198.51.100.9"} for _ in range(10)]
                + [{"message": "payment with card 4111111111111111"}]
            )}
        self.assertTrue({"error_spike", "server_errors_spike", "attack_probes", "brute_force", "secrets_logged"} <= rules)
        stored = LogEvent.objects.get(message__contains="payment")
        self.assertIn("[REDACTED:card_number]", stored.message)
        self.assertEqual(stored.redacted, ["card_number"])


@patch("apps.logs.tasks.analyze_events.delay")
class AppIngestTests(AppFixture):
    def test_pythons_own_http_handler_with_basic_auth(self, delay):
        form = urlencode({"name": "billing", "msg": "Invoice failed", "levelname": "ERROR", "created": time.time(),
                          "exc_text": PY_TRACE})
        auth = base64.b64encode(f"densight:{self.key}".encode()).decode()
        response = self.client.post("/api/ingest/", data=form, content_type="application/x-www-form-urlencoded",
                                    HTTP_AUTHORIZATION=f"Basic {auth}")
        self.assertEqual(response.status_code, 202)
        event = LogEvent.objects.get()
        self.assertEqual((event.program, event.category), ("billing", "app_error"))
        self.assertTrue(event.fingerprint)
        self.assertEqual(len(delay.call_args.args[3]), 1)  # one new error group, handed to the analysis

    def test_error_groups_api(self, _):
        store(self.app, [python_error()])
        group = ErrorGroup.objects.get()
        self.client.force_login(self.users["viewer"])
        listed = self.client.get(f"/api/error-groups/?organization={self.org.id}&status=unresolved").json()
        self.assertEqual(listed["results"][0]["exception_type"], "KeyError")
        self.assertEqual(self.client.post(f"/api/error-groups/{group.id}/set-status/", {"status": "resolved"},
                                          content_type=JSON).status_code, 403)
        self.client.force_login(self.users["analyst"])
        self.assertEqual(self.client.post(f"/api/error-groups/{group.id}/set-status/", {"status": "resolved"},
                                          content_type=JSON).json()["status"], "resolved")
        events = self.client.get(f"/api/log-events/?organization={self.org.id}&fingerprint={group.fingerprint}").json()
        self.assertEqual(events["count"], 1)
        overview = self.client.get(f"/api/logs/overview/?organization={self.org.id}").json()
        self.assertEqual((overview["applications"], overview["errors_24h"]), (1, 1))

    def test_client_files_download(self, _):
        response = self.client.get("/api/logs/clients/densight_logging.py")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"class DensightHandler", b"".join(response.streaming_content))
        self.assertEqual(self.client.get("/api/logs/clients/../settings.py").status_code, 404)


@override_settings(LOG_INGEST_MAX_REQUESTS_PER_MINUTE=1000)
class PythonHandlerEndToEndTests(LiveServerTestCase):
    """The shipped handler, sending to a real running server."""

    def test_records_and_exceptions_arrive(self):
        from apps.logs.clients.densight_logging import DensightHandler

        org = Organization.objects.create(name="Live", root_domain="live.com")
        source = LogSource(organization=org, name="worker", os=LogSource.OS.PYTHON)
        key = source.issue_key()
        source.save()
        handler = DensightHandler(f"{self.live_server_url}/api/ingest/", key, service="worker", flush_interval=0.2,
                                  release="1.2.3")
        logger = logging.getLogger("densight-e2e")
        logger.propagate = False
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        with patch("apps.logs.tasks.analyze_events.delay"):
            logger.info("job started", extra={"job_id": 17})
            try:
                {}["missing"]
            except KeyError:
                logger.exception("job failed")
            for _ in range(50):
                if LogEvent.objects.filter(source=source).count() >= 2:
                    break
                time.sleep(0.1)
        logger.removeHandler(handler)
        events = {e.message: e for e in LogEvent.objects.filter(source=source)}
        self.assertEqual(events["job started"].raw["job_id"], 17)
        failed = next(e for m, e in events.items() if m.startswith("job failed"))
        self.assertEqual((failed.category, failed.service), ("app_error", "worker"))
        group = ErrorGroup.objects.get(source=source)
        self.assertEqual((group.exception_type, group.first_release), ("KeyError", "1.2.3"))
        self.assertLess(abs((timezone.now() - failed.occurred_at).total_seconds()), 60)
        self.assertEqual(LogDetection.objects.count(), 0)  # analysis runs in the worker, patched out here


@override_settings(LOG_INGEST_MAX_REQUESTS_PER_MINUTE=1000)
class PythonHandlerAfterForkTests(LiveServerTestCase):
    """Celery and gunicorn create the handler, then fork: the child needs its own sender thread."""

    def test_a_forked_child_still_sends(self):
        import multiprocessing

        from apps.logs.clients.densight_logging import DensightHandler

        org = Organization.objects.create(name="Fork", root_domain="fork.com")
        source = LogSource(organization=org, name="worker", os=LogSource.OS.PYTHON)
        key = source.issue_key()
        source.save()
        handler = DensightHandler(f"{self.live_server_url}/api/ingest/", key, service="worker", flush_interval=0.2)

        def child():
            logger = logging.getLogger("densight-fork")
            logger.propagate = False
            logger.addHandler(handler)
            logger.warning("from the forked child")
            time.sleep(1.5)

        with patch("apps.logs.tasks.analyze_events.delay"):
            process = multiprocessing.get_context("fork").Process(target=child)
            process.start()
            process.join(10)
            for _ in range(50):
                if LogEvent.objects.filter(source=source).exists():
                    break
                time.sleep(0.1)
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(list(LogEvent.objects.filter(source=source).values_list("message", flat=True)),
                         ["from the forked child"])


class SelfLoggingFilterTests(SimpleTestCase):
    """Densight sending its own logs must not log its own log handling (a feedback loop)."""

    def test_the_log_pipeline_is_skipped_everything_else_is_sent(self):
        from apps.logs.self_logging import SkipLogPipeline

        def record(name, message):
            return logging.LogRecord(name, logging.INFO, __file__, 1, message, (), None)

        keep = SkipLogPipeline().filter
        self.assertFalse(keep(record("apps.logs", "log_batch_stored")))
        self.assertFalse(keep(record("django.server", '"POST /api/ingest/ HTTP/1.1" 202')))
        self.assertFalse(keep(record("django.request", "Too Many Requests: /api/ingest/")))
        self.assertFalse(keep(record("celery.app.trace", "Task apps.logs.tasks.analyze_events[1] succeeded")))
        self.assertTrue(keep(record("apps.scanning", "scan_job_failed")))
        self.assertTrue(keep(record("django.request", "Internal Server Error: /api/findings/")))
