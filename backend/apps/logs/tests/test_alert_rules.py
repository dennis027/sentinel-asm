"""
The organization's own log alerts, and release tracking for app errors.
"""

import time


from apps.logs.models import ErrorGroup, LogAlertRule, LogDetection, LogSource

from .test_app_logs import AppFixture, python_error


def line(message, level="INFO", **extra):
    return {"timestamp": time.time(), "level": level, "logger": "payments", "message": message, **extra}


class CustomAlertTests(AppFixture):
    def rule(self, **fields):
        return LogAlertRule.objects.create(organization=self.org, name="Payments declined",
                                           contains="payment declined", **fields)

    def test_fires_once_the_threshold_is_reached_within_the_window(self):
        rule = self.rule(threshold=5, window_minutes=5, severity="high")
        self.ingest([line("Payment declined for order 1"), line("all good")] * 2)
        self.assertFalse(LogDetection.objects.filter(rule=rule.rule_id).exists())

        new = self.ingest([line(f"PAYMENT DECLINED for order {n}") for n in range(3)])
        detection = LogDetection.objects.get(rule=rule.rule_id)
        self.assertEqual([d.id for d in new], [detection.id])
        self.assertEqual((detection.severity, detection.event_count), ("high", 5))
        self.assertIn("Payments declined: 5 on orders-api", detection.title)
        rule.refresh_from_db()
        self.assertIsNotNone(rule.last_fired_at)

        # More of the same updates that detection rather than adding more.
        self.ingest([line("payment declined again")])
        self.assertEqual(LogDetection.objects.filter(rule=rule.rule_id).count(), 1)
        self.assertEqual(LogDetection.objects.get(rule=rule.rule_id).event_count, 6)

    def test_old_matches_outside_the_window_do_not_count(self):
        rule = self.rule(threshold=3, window_minutes=5)
        old = time.time() - 3600
        self.ingest([line("payment declined", timestamp=old)] * 2)
        self.ingest([line("payment declined")])
        self.assertFalse(LogDetection.objects.filter(rule=rule.rule_id).exists())

    def test_filters_and_disabled_rules(self):
        errors_only = LogAlertRule.objects.create(organization=self.org, name="Any error", category="app_error",
                                                  level="error", threshold=1)
        off = self.rule(enabled=False)
        elsewhere = LogSource.objects.create(organization=self.org, name="other", os=LogSource.OS.NODE, key_hash="x")
        scoped = self.rule(source=elsewhere)
        self.ingest([line("payment declined"), python_error()])
        self.assertEqual(LogDetection.objects.filter(rule=errors_only.rule_id).count(), 1)
        self.assertFalse(LogDetection.objects.filter(rule__in=[off.rule_id, scoped.rule_id]).exists())

    def test_api_permissions_validation_and_preview(self):
        self.ingest([line("payment declined for order 7")])
        body = {"organization": str(self.org.id), "name": "Declines", "contains": "payment declined",
                "threshold": 10, "window_minutes": 5, "severity": "high"}

        self.client.force_login(self.users["viewer"])
        self.assertEqual(self.client.post("/api/log-alert-rules/", body, content_type="application/json").status_code, 403)

        self.client.force_login(self.users["analyst"])
        preview = self.client.post("/api/log-alert-rules/preview/", body, content_type="application/json").json()
        self.assertEqual(preview["matches_24h"], 1)
        self.assertIn("order 7", preview["examples"][0]["message"])

        created = self.client.post("/api/log-alert-rules/", body, content_type="application/json")
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.json()["matches_24h"], 1)
        rule_id = created.json()["id"]

        bad = self.client.post("/api/log-alert-rules/", {**body, "contains": "", "window_minutes": 0,
                                                         "severity": "urgent"}, content_type="application/json")
        self.assertEqual(set(bad.json()), {"window_minutes", "severity"})
        empty = self.client.post("/api/log-alert-rules/", {**body, "contains": ""}, content_type="application/json")
        self.assertIn("contains", empty.json())

        other = self.org.__class__.objects.create(name="Other", root_domain="other.com")
        foreign = LogSource.objects.create(organization=other, name="x", os="python", key_hash="y")
        self.assertIn("source", self.client.post("/api/log-alert-rules/", {**body, "source": str(foreign.id)},
                                                 content_type="application/json").json())

        toggled = self.client.patch(f"/api/log-alert-rules/{rule_id}/", {"enabled": False},
                                    content_type="application/json")
        self.assertFalse(toggled.json()["enabled"])
        listed = self.client.get(f"/api/log-alert-rules/?organization={self.org.id}").json()
        self.assertEqual([r["name"] for r in listed], ["Declines"])
        self.assertEqual(self.client.delete(f"/api/log-alert-rules/{rule_id}/").status_code, 204)


class ReleaseTrackingTests(AppFixture):
    def test_errors_remember_the_release_that_introduced_them_and_the_one_that_brought_them_back(self):
        self.ingest([line("started", release="2.14.0")])
        new = self.ingest([python_error() | {"release": "2.15.0"}])
        group = ErrorGroup.objects.get()
        self.assertEqual((group.first_release, group.last_release), ("2.15.0", "2.15.0"))
        self.assertIn("(release 2.15.0)", new[0].title)

        group.status = ErrorGroup.Status.RESOLVED
        group.save()
        back = self.ingest([python_error() | {"release": "2.15.2"}])
        group.refresh_from_db()
        self.assertEqual((group.first_release, group.last_release), ("2.15.0", "2.15.2"))
        regressed = next(d for d in back if d.rule == "error_regressed")
        self.assertIn("Came back in release 2.15.2; it first appeared in 2.15.0.", regressed.description)

    def test_releases_endpoint_and_filter(self):
        self.ingest([line("started", release="2.14.0", timestamp=time.time() - 7200)])
        self.ingest([python_error() | {"release": "2.15.0"}, line("ok", release="2.15.0")])
        self.client.force_login(self.users["viewer"])
        releases = self.client.get(f"/api/error-groups/releases/?organization={self.org.id}").json()
        self.assertEqual([(r["release"], r["events"], r["errors"], r["new_errors"]) for r in releases],
                         [("2.15.0", 2, 1, 1), ("2.14.0", 1, 0, 0)])
        groups = self.client.get(f"/api/error-groups/?organization={self.org.id}&release=2.15.0").json()
        self.assertEqual(groups["count"], 1)
        self.assertEqual(groups["results"][0]["first_release"], "2.15.0")
        none = self.client.get(f"/api/error-groups/?organization={self.org.id}&release=2.14.0").json()
        self.assertEqual(none["count"], 0)

    def test_pino_and_node_version_fields(self):
        from apps.logs.normalize import normalize

        self.assertEqual(normalize({"msg": "x", "level": 30, "version": "3.8.2"}, app=True).release, "3.8.2")
        self.assertEqual(normalize({"message": "x", "service": {"name": "a", "version": "9"}}, app=True).release, "9")
        self.assertEqual(normalize({"message": "x", "release": {"bad": 1}}, app=True).release, "")
