"""The log search: filters, counts per option, the timeline, live updates and CSV export."""

import csv
import io
import time
from datetime import timedelta

from django.utils import timezone

from apps.logs.models import LogDetection, LogEvent

from .test_app_logs import AppFixture


def line(message, minutes_ago=1, **extra):
    return {"timestamp": time.time() - minutes_ago * 60, "message": message, **extra}


class SearchTests(AppFixture):
    def setUp(self):
        super().setUp()
        self.ingest([
            line("checkout ok", level="INFO", service="shop", release="2.15.0", host="web-1"),
            line("slow query", level="WARNING", service="shop", release="2.15.0", host="web-2"),
            line("payment failed", level="ERROR", service="payments", release="3.8.2", host="web-1"),
            line("=HYPERLINK(\"evil\")", level="INFO", service="payments", release="3.8.2", host="web-1"),
            line("old one", 60 * 30, level="ERROR", service="shop", release="2.14.0", host="web-1"),
        ])
        self.client.force_login(self.users["viewer"])
        self.base = f"/api/log-events/?organization={self.org.id}"

    def messages(self, query):
        return sorted(e["message"] for e in self.client.get(self.base + query).json()["results"])

    def test_filters(self):
        self.assertEqual(self.messages("&level=problems"), ["payment failed", "slow query"])
        self.assertEqual(self.messages("&service=shop"), ["checkout ok", "slow query"])
        self.assertEqual(self.messages("&release=3.8.2&level=error"), ["payment failed"])
        self.assertEqual(self.messages("&host=WEB-2"), ["slow query"])
        self.assertEqual(self.messages("&q=payments&level=error"), ["payment failed"])  # q searches service too
        self.assertEqual(self.messages("&since=all&release=2.14.0"), ["old one"])
        after = (timezone.now() - timedelta(hours=40)).isoformat()
        before = (timezone.now() - timedelta(hours=20)).isoformat()
        self.assertEqual(self.messages(f"&since=custom&after={after}&before={before}".replace("+", "%2B")), ["old one"])
        self.assertEqual(self.client.get(self.base + "&after=yesterday").status_code, 400)

    def test_live_updates_only_return_what_is_new(self):
        newest = max(e["id"] for e in self.client.get(self.base).json()["results"])
        self.assertEqual(self.messages(f"&after_id={newest}"), [])
        self.ingest([line("just arrived", level="INFO", service="shop")])
        self.assertEqual(self.messages(f"&after_id={newest}"), ["just arrived"])

    def test_facets_count_each_option_with_the_other_filters_applied(self):
        facets = self.facets("&service=shop")
        self.assertEqual(facets["level"], {"info": 1, "warning": 1})
        # The service counts ignore the service filter itself, so other services stay choosable.
        self.assertEqual(sorted(map(tuple, facets["service"])), [("payments", 2), ("shop", 2)])
        self.assertEqual(facets["release"], [["2.15.0", 2]])
        self.assertEqual(facets["source"], {str(self.app.id): 2})
        self.assertEqual(self.client.get("/api/log-events/facets/").status_code, 400)

    def facets(self, query=""):
        return self.client.get(f"/api/log-events/facets/?organization={self.org.id}{query}").json()

    def test_timeline(self):
        body = self.client.get(f"/api/log-events/timeline/?organization={self.org.id}&since=1h").json()
        self.assertEqual(body["bucket_seconds"], 60)
        self.assertLessEqual(len(body["buckets"]), 62)
        totals = {k: sum(b[k] for b in body["buckets"]) for k in ("error", "warning", "info")}
        self.assertEqual(totals, {"error": 1, "warning": 1, "info": 2})
        week = self.client.get(f"/api/log-events/timeline/?organization={self.org.id}&since=7d").json()
        self.assertEqual(week["bucket_seconds"], 3 * 3600)

    def test_csv_export_is_filtered_and_safe_in_spreadsheets(self):
        response = self.client.get(f"/api/log-events/export/?organization={self.org.id}&service=payments")
        self.assertEqual(response["Content-Type"], "text/csv")
        rows = list(csv.reader(io.StringIO(b"".join(response.streaming_content).decode())))
        self.assertEqual(rows[0][:3], ["occurred_at", "source", "host"])
        self.assertEqual(sorted(r[-1] for r in rows[1:]), ["'=HYPERLINK(\"evil\")", "payment failed"])

    def test_other_organizations_events_never_show(self):
        other = self.org.__class__.objects.create(name="Other", root_domain="other.com")
        self.assertEqual(self.client.get(f"/api/log-events/?organization={other.id}").json()["count"], 0)
        self.assertEqual(self.facets().get("level"), {"info": 2, "warning": 1, "error": 1})


class DetectionFilterTests(AppFixture):
    def test_text_and_rule_filters(self):
        for rule, title in [("brute_force", "Many failed sign-ins from 203.0.113.9"),
                            ("custom:abc", "Payments failing: 12 on shop"), ("new_error", "New error in shop: KeyError")]:
            LogDetection.objects.create(organization=self.org, source=self.app, rule=rule, severity="high", title=title,
                                        first_seen=timezone.now(), last_seen=timezone.now())
        self.client.force_login(self.users["viewer"])
        base = f"/api/log-detections/?organization={self.org.id}"

        def titles(query):
            return [d["title"] for d in self.client.get(base + query).json()["results"]]

        self.assertEqual(titles("&rule=custom"), ["Payments failing: 12 on shop"])
        self.assertEqual(titles("&q=keyerror"), ["New error in shop: KeyError"])
        self.assertEqual(titles("&rule=brute_force"), ["Many failed sign-ins from 203.0.113.9"])
        self.assertEqual(LogEvent.objects.count(), 0)
