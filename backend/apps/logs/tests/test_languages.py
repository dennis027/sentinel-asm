"""
Application logs from every supported language, as each library really
writes them: the level, message, exception type and the place in the
app's own code that groups repeats of an error.
"""

from django.test import SimpleTestCase

from apps.logs.normalize import normalize

JAVA_TRACE = (
    "java.lang.IllegalStateException: Cart is empty\n"
    "\tat com.acme.orders.CheckoutService.charge(CheckoutService.java:42)\n"
    "\tat com.acme.orders.CheckoutController.post(CheckoutController.java:18)\n"
    "\tat org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)\n"
    "\tat java.base/java.lang.Thread.run(Thread.java:1583)\n"
)
JAVA_TRACE_WRAPPED = (
    "java.lang.NullPointerException: Cannot invoke \"String.length()\" because \"s\" is null\n"
    "\tat org.springframework.util.StringUtils.hasText(StringUtils.java:12)\n"
    "\tat com.acme.orders.CheckoutService.charge(CheckoutService.java:57)\n"
)
DOTNET_TRACE = (
    "System.InvalidOperationException: Sequence contains no elements\n"
    "   at System.Linq.ThrowHelper.ThrowNoElementsException()\n"
    "   at Acme.Orders.CheckoutService.Charge(Cart cart) in /src/Acme.Orders/CheckoutService.cs:line 42\n"
    "   at Microsoft.AspNetCore.Mvc.Infrastructure.ActionMethodExecutor.Execute(Object controller)\n"
)
PHP_TRACE = (
    "RuntimeException: Payment gateway refused in /var/www/html/app/Services/Payment.php:31\n"
    "Stack trace:\n"
    "#0 /var/www/html/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php(128): App\\Services\\Payment->charge()\n"
    "#1 /var/www/html/app/Http/Controllers/OrderController.php(42): App\\Services\\Payment->charge(Object(App\\Models\\Order))\n"
    "#2 {main}"
)
RUBY_TRACE = (
    "NoMethodError: undefined method `total' for nil\n"
    "/usr/local/bundle/gems/actionpack-7.1.3/lib/action_controller/metal/basic_implicit_render.rb:6:in `send_action'\n"
    "/app/app/models/order.rb:42:in `total'\n"
    "/app/app/controllers/orders_controller.rb:12:in `create'\n"
)
GO_STACK = (
    "main.(*Server).checkout\n\t/app/internal/orders/handler.go:42\n"
    "net/http.HandlerFunc.ServeHTTP\n\t/usr/local/go/src/net/http/server.go:2136\n"
)


def app(record):
    return normalize(record, app=True)


class LanguageTests(SimpleTestCase):
    def assertError(self, event, kind, culprit, level="error"):
        self.assertEqual((event.category, event.level, event.exception_type, event.culprit),
                         ("app_error", level, kind, culprit))
        self.assertTrue(event.fingerprint)

    def test_java_logback_logstash_encoder(self):
        event = app({"@timestamp": "2026-10-17T09:00:00.123+02:00", "@version": "1", "message": "Checkout failed",
                     "logger_name": "com.acme.orders.CheckoutService", "thread_name": "http-nio-8080-exec-3",
                     "level": "ERROR", "level_value": 40000, "stack_trace": JAVA_TRACE})
        self.assertError(event, "java.lang.IllegalStateException", "CheckoutService.java in com.acme.orders.CheckoutService.charge")
        self.assertEqual((event.program, event.occurred_at.isoformat()), ("com.acme.orders.CheckoutService", "2026-10-17T09:00:00.123000+02:00"))
        # A library frame on top: still blamed on the app's own code.
        self.assertEqual(app({"message": "x", "level": "ERROR", "stack_trace": JAVA_TRACE_WRAPPED}).culprit,
                         "CheckoutService.java in com.acme.orders.CheckoutService.charge")

    def test_java_log4j2_ecs_layout(self):
        event = app({"@timestamp": "2026-10-17T09:00:00Z", "log.level": "ERROR", "message": "Checkout failed",
                     "log.logger": "com.acme.orders", "error.type": "java.lang.IllegalStateException",
                     "error.message": "Cart is empty", "error.stack_trace": JAVA_TRACE})
        self.assertError(event, "java.lang.IllegalStateException", "CheckoutService.java in com.acme.orders.CheckoutService.charge")

    def test_dotnet_serilog_compact_json(self):
        event = app({"@t": "2026-10-17T09:00:00.0000000Z", "@mt": "Checkout failed for order {OrderId}",
                     "@l": "Error", "@x": DOTNET_TRACE, "OrderId": 42, "SourceContext": "Acme.Orders.CheckoutService",
                     "RequestPath": "/api/checkout"})
        self.assertError(event, "System.InvalidOperationException", "Acme.Orders/CheckoutService.cs in Acme.Orders.CheckoutService.Charge")
        self.assertIn("Checkout failed for order 42", event.message)
        self.assertEqual(event.program, "Acme.Orders.CheckoutService")
        # No "@l" means Information in CLEF.
        self.assertEqual(app({"@t": "2026-10-17T09:00:00Z", "@mt": "Started"}).level, "info")

    def test_dotnet_console_json_and_serilog_http_sink(self):
        console = app({"Timestamp": "2026-10-17T09:00:00Z", "EventId": 0, "LogLevel": "Error",
                       "Category": "Acme.Orders.CheckoutService", "Message": "Checkout failed", "Exception": DOTNET_TRACE})
        self.assertError(console, "System.InvalidOperationException", "Acme.Orders/CheckoutService.cs in Acme.Orders.CheckoutService.Charge")
        sink = app({"Timestamp": "2026-10-17T09:00:00Z", "Level": "Warning", "MessageTemplate": "Slow {Ms}",
                    "RenderedMessage": "Slow 900", "Properties": {"Ms": 900, "RequestPath": "/api/cart",
                                                                  "StatusCode": 503, "RequestMethod": "GET"}})
        self.assertEqual((sink.message, sink.http_status, sink.category), ("Slow 900", 503, "http_request"))

    def test_php_monolog_json_and_densight_handler(self):
        handler = app({"timestamp": "2026-10-17T09:00:00.000000+00:00", "level": "ERROR", "logger": "production",
                       "message": "Payment failed", "service": "shop",
                       "exception": {"type": "RuntimeException", "value": "Payment gateway refused", "stacktrace": PHP_TRACE},
                       "method": "POST", "path": "/checkout", "ip": "203.0.113.5"})
        # Where it was thrown, in the app's code: Payment.php, in the method frame #0 names.
        self.assertError(handler, "RuntimeException", "app/Services/Payment.php in App\\Services\\Payment->charge")
        self.assertEqual(handler.src_ip, "203.0.113.5")
        # Monolog's own JsonFormatter: numeric level, context, normalized exception.
        monolog = app({"message": "Payment failed", "level": 400, "level_name": "ERROR", "channel": "app",
                       "datetime": "2026-10-17T09:00:00.000000+00:00", "extra": {},
                       "context": {"user_id": 7, "exception": {
                           "class": "RuntimeException", "message": "Payment gateway refused", "code": 0,
                           "file": "/var/www/html/app/Services/Payment.php:31",
                           "trace": ["/var/www/html/vendor/laravel/framework/src/Pipeline.php:128",
                                     "/var/www/html/app/Http/Controllers/OrderController.php:42"]}}})
        self.assertEqual((monolog.level, monolog.exception_type, monolog.program, monolog.user),
                         ("error", "RuntimeException", "app", "7"))
        self.assertEqual(monolog.culprit, "app/Services/Payment.php")
        self.assertEqual(app({"message": "x", "level": 300, "level_name": "WARNING", "channel": "app",
                              "datetime": "2026-10-17T09:00:00+00:00"}).level, "warning")

    def test_ruby_logger_and_lograge(self):
        event = app({"timestamp": "2026-10-17T09:00:00.000000Z", "level": "ERROR", "logger": "", "service": "shop",
                     "message": "NoMethodError: undefined method `total' for nil",
                     "exception": {"type": "NoMethodError", "value": "undefined method `total' for nil",
                                   "stacktrace": RUBY_TRACE}})
        self.assertError(event, "NoMethodError", "app/models/order.rb in total")
        lograge = app({"method": "POST", "path": "/login", "format": "html", "controller": "SessionsController",
                       "action": "create", "status": 401, "duration": 12.3, "remote_ip": "198.51.100.9"})
        self.assertEqual((lograge.category, lograge.src_ip), ("auth_failure", "198.51.100.9"))

    def test_go_slog_zap_and_panics(self):
        slog = app({"timestamp": "2026-10-17T09:00:00Z", "level": "ERROR", "message": "checkout failed",
                    "service": "orders", "error": {"type": "*fs.PathError", "message": "open /data/x: no such file",
                                                    "stack": GO_STACK}})
        self.assertError(slog, "*fs.PathError", "internal/orders/handler.go in main.(*Server).checkout")
        zap = app({"level": "error", "ts": 1792227600.123, "caller": "orders/handler.go:42", "msg": "checkout failed",
                   "error": "open /data/x: no such file or directory", "stacktrace": GO_STACK})
        self.assertEqual((zap.category, zap.level, zap.culprit),
                         ("app_error", "error", "internal/orders/handler.go in main.(*Server).checkout"))
        self.assertEqual(zap.occurred_at.year, 2026)
        # The same error from another request: grouped.
        again = app({"level": "error", "ts": 1792227700, "msg": "checkout failed",
                     "error": "open /data/y: no such file or directory", "stacktrace": GO_STACK})
        self.assertEqual(zap.fingerprint, again.fingerprint)
        panic = app({"level": "ERROR", "message": "panic: runtime error: index out of range [5] with length 3",
                     "error": {"type": "densight.PanicError", "message": "runtime error: index out of range",
                               "stack": GO_STACK}})
        self.assertEqual(panic.exception_type, "densight.PanicError")

    def test_numeric_levels_from_each_library(self):
        for level, expected in [(50, "error"), (40, "warning"), (30, "info"), (400, "error"), (300, "warning"),
                                (250, "info"), (40000, "error"), (30000, "warning"), (20000, "info"), (3, "error"),
                                (4, "warning"), (6, "info"), ("Information", "info"), ("SEVERE", "error"),
                                ("Critical", "error"), ("dpanic", "error")]:
            self.assertEqual(app({"message": "m", "level": level}).level, expected, level)

    def test_php_exception_thrown_inside_a_library_is_blamed_on_the_app(self):
        stack = ("GuzzleHttp\\Exception\\ConnectException: timed out in /var/www/html/vendor/guzzlehttp/guzzle/src/Client.php:211\n"
                 "Stack trace:\n#0 /var/www/html/vendor/guzzlehttp/guzzle/src/Client.php(120): GuzzleHttp\\Client->send()\n"
                 "#1 /var/www/html/app/Services/Payment.php(31): GuzzleHttp\\Client->post()\n#2 {main}")
        event = app({"level": "ERROR", "message": "x", "exception": {"type": "GuzzleHttp\\Exception\\ConnectException",
                                                                    "value": "timed out", "stacktrace": stack}})
        self.assertEqual(event.culprit, "app/Services/Payment.php in GuzzleHttp\\Client->post")

    def test_gelf(self):
        event = app({"version": "1.1", "host": "web-3", "short_message": "Disk almost full", "level": 4,
                     "timestamp": 1792227600.5, "_service": "api"})
        self.assertEqual((event.message, event.level, event.host), ("Disk almost full", "warning", "web-3"))
