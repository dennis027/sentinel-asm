"""
Server logs: parsing what Linux and Windows shippers send, the ingest
endpoint (keys, limits, formats), the detections, and who may see and
change what.
"""

import gzip
import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.logs.detections import analyze, check_silent_sources
from apps.logs.ingest import store
from apps.logs.models import LogDetection, LogEvent, LogSource
from apps.logs.normalize import normalize
from apps.logs.tasks import analyze_events, purge_old_log_events
from apps.notifications.models import NotificationRule
from apps.organizations.deletion import delete_organization
from apps.organizations.models import Membership, Organization

JSON = "application/json"


def journald(message, program="sshd", host="web-01", **extra):
    return {"date": timezone.now().timestamp(), "_HOSTNAME": host, "SYSLOG_IDENTIFIER": program,
            "PRIORITY": "6", "MESSAGE": message, **extra}


def windows(event_id, inserts=(), message="", channel="Security", computer="DC-01"):
    return {"EventID": event_id, "Channel": channel, "Computer": computer, "Level": 0,
            "TimeCreated": timezone.now().isoformat(), "StringInserts": list(inserts), "Message": message}


def failed_4625(user="administrator", ip="198.51.100.20", logon_type="3"):
    inserts = ["S-1-0-0", "-", "-", "0x0", "S-1-0-0", user, "CORP", "0xc000006d", "%%2313", "0xc000006a",
               logon_type, "NtLmSsp", "NTLM", "WS1", "-", "-", "0", "0x0", "-", ip, "51515"]
    return windows(4625, inserts)


class NormalizeTests(SimpleTestCase):
    def test_linux_ssh_failure_from_journald(self):
        event = normalize(journald("Failed password for invalid user oracle from 203.0.113.9 port 51234 ssh2"))
        self.assertEqual((event.category, event.action), ("auth_failure", "ssh_failed_login"))
        self.assertEqual((event.user, event.src_ip, event.host, event.program), ("oracle", "203.0.113.9", "web-01", "sshd"))
        self.assertEqual(event.level, "warning")

    def test_fluent_bit_strip_underscores_and_raw_syslog_lines(self):
        event = normalize({"date": 1760000000.5, "HOSTNAME": "db-01", "SYSLOG_IDENTIFIER": "sshd",
                           "MESSAGE": "Accepted publickey for deploy from 10.0.0.5 port 2222 ssh2"})
        self.assertEqual((event.category, event.user, event.src_ip, event.host), ("auth_success", "deploy", "10.0.0.5", "db-01"))
        self.assertEqual(event.occurred_at.year, 2025)
        line = normalize({"log": "Oct 17 10:00:01 web-02 sudo[812]:    alice : user NOT in sudoers ; TTY=pts/0 ; "
                                 "PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"})
        self.assertEqual((line.host, line.program, line.action, line.user), ("web-02", "sudo", "sudo_denied", "alice"))

    def test_admin_group_and_log_wiping_on_linux(self):
        self.assertEqual(normalize(journald("add 'mallory' to group 'sudo'", program="usermod")).action,
                         "admin_group_added")
        self.assertEqual(normalize(journald("add 'bob' to group 'docker'", program="usermod")).action,
                         "group_member_added")
        wipe = normalize(journald("bob : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/rm -rf /var/log/auth.log",
                                  program="sudo"))
        self.assertEqual((wipe.category, wipe.action), ("log_tampering", "logs_deleted"))

    def test_windows_failed_logon_reads_user_address_and_rdp(self):
        event = normalize(failed_4625(logon_type="10"))
        self.assertEqual(event.event_id, 4625)
        self.assertEqual((event.category, event.action), ("auth_failure", "windows_logon_failed_rdp"))
        self.assertEqual((event.user, event.src_ip, event.host, event.program),
                         ("administrator", "198.51.100.20", "DC-01", "Security"))
        # No message text from Windows: a readable one is written.
        self.assertEqual(event.message, "An account failed to sign in: administrator from 198.51.100.20")

    def test_windows_falls_back_to_the_message_text(self):
        message = ("An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tNULL SID\r\n\tAccount Name:\t\t-\r\n"
                   "Account For Which Logon Failed:\r\n\tSecurity ID:\t\tNULL SID\r\n\tAccount Name:\t\tsvc_backup\r\n"
                   "Network Information:\r\n\tSource Network Address:\t203.0.113.44\r\n")
        event = normalize(windows(4625, message=message))
        self.assertEqual((event.user, event.src_ip), ("svc_backup", "203.0.113.44"))

    def test_windows_admin_added_and_log_cleared(self):
        added = normalize(windows(4732, ["eve", "S-1-5-21-1", "Administrators", "S-1-5-32-544", "S-1-5-21-2", "it-admin"]))
        self.assertEqual((added.category, added.action, added.user), ("privilege", "admin_group_added", "eve"))
        self.assertEqual(normalize(windows(1102, ["S-1-5-21", "attacker"])).action, "logs_cleared")
        self.assertEqual(normalize(windows(104, channel="System")).action, "logs_cleared")
        self.assertEqual(normalize(windows(104, channel="Application")).action, "")

    def test_generic_records_and_odd_input(self):
        event = normalize({"timestamp": "2026-01-05T08:00:00Z", "host": "app-1", "program": "myapp",
                           "message": "boom", "level": "error"})
        self.assertEqual((event.host, event.level, event.occurred_at.hour), ("app-1", "error", 8))
        self.assertEqual(normalize("just text").message, "just text")
        future = normalize({"timestamp": "2099-01-01T00:00:00Z", "message": "clock skew"})
        self.assertLess(future.occurred_at, timezone.now() + timedelta(minutes=6))


class LogFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Acme", root_domain="acme.com")
        cls.users = {}
        for role in Membership.Role.values:
            cls.users[role] = User.objects.create_user(role, password="pass12345!")
            Membership.objects.create(user=cls.users[role], organization=cls.org, role=role)
        cls.outsider = User.objects.create_user("outsider", password="pass12345!")

    def setUp(self):
        cache.clear()
        self.source = LogSource(organization=self.org, name="web-01", os=LogSource.OS.LINUX)
        self.key = self.source.issue_key()
        self.source.save()

    def send(self, body, key=None, **headers):
        payload = body if isinstance(body, (bytes, str)) else json.dumps(body)
        return self.client.post("/api/ingest/", data=payload, content_type=JSON,
                                HTTP_AUTHORIZATION=f"Bearer {key or self.key}", **headers)


@patch("apps.logs.tasks.analyze_events.delay", side_effect=lambda *a: analyze_events(*a))
class IngestTests(LogFixture):
    def test_a_batch_is_stored_and_the_server_marked_as_receiving(self, _):
        response = self.send([journald("Failed password for root from 203.0.113.9 port 1 ssh2"),
                              journald("Started Session 4 of user deploy.", program="systemd")])
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {"accepted": 2})
        self.source.refresh_from_db()
        self.assertEqual((self.source.events_received, self.source.last_host, self.source.status), (2, "web-01", "receiving"))
        self.assertEqual(LogEvent.objects.filter(organization=self.org).count(), 2)

    def test_ndjson_single_records_and_gzip(self, _):
        lines = "\n".join(json.dumps(journald(f"line {i}")) for i in range(3))
        self.assertEqual(self.send(lines).json()["accepted"], 3)
        self.assertEqual(self.send(journald("one")).json()["accepted"], 1)
        compressed = gzip.compress(json.dumps([journald("zipped")]).encode())
        response = self.client.post("/api/ingest/", data=compressed, content_type=JSON,
                                    HTTP_AUTHORIZATION=f"Bearer {self.key}", HTTP_CONTENT_ENCODING="gzip")
        self.assertEqual(response.json()["accepted"], 1)

    def test_keys_are_required_and_specific(self, _):
        self.assertEqual(self.client.post("/api/ingest/", data="[]", content_type=JSON).status_code, 401)
        self.assertEqual(self.send([journald("x")], key="dsl_wrong").status_code, 401)
        old = self.key
        self.source.issue_key()
        self.source.save()
        self.assertEqual(self.send([journald("x")], key=old).status_code, 401)
        self.assertEqual(self.client.get("/api/ingest/").status_code, 405)

    @override_settings(LOG_INGEST_MAX_BYTES=2000, LOG_INGEST_MAX_RECORDS=5, LOG_INGEST_MAX_REQUESTS_PER_MINUTE=3)
    def test_limits(self, _):
        self.assertEqual(self.send([journald("x" * 3000)]).status_code, 413)
        self.assertEqual(self.send([{"message": "a"}] * 6).status_code, 413)
        self.assertEqual(self.send("not json").status_code, 400)
        cache.clear()
        statuses = [self.send([{"message": "a"}]).status_code for _ in range(4)]
        self.assertEqual(statuses, [202, 202, 202, 429])
        bomb = gzip.compress(b"[" + b'{"message":"a"},' * 5000 + b'{"message":"a"}]')
        cache.clear()
        response = self.client.post("/api/ingest/", data=bomb, content_type=JSON,
                                    HTTP_AUTHORIZATION=f"Bearer {self.key}", HTTP_CONTENT_ENCODING="gzip")
        self.assertEqual(response.status_code, 413)


class DetectionTests(LogFixture):
    def ingest(self, records):
        return analyze(self.source, store(self.source, records))

    def test_brute_force_then_a_successful_login_is_critical(self):
        new = self.ingest([journald(f"Failed password for admin from 203.0.113.9 port {i} ssh2") for i in range(12)])
        self.assertEqual([d.rule for d in new], ["brute_force"])
        self.assertEqual(new[0].event_count, 12)
        # More failures update the same detection rather than adding one.
        self.assertEqual(self.ingest([journald("Failed password for admin from 203.0.113.9 port 99 ssh2")]), [])
        self.assertEqual(LogDetection.objects.get(rule="brute_force").event_count, 13)
        login = self.ingest([journald("Accepted password for admin from 203.0.113.9 port 7 ssh2")])
        self.assertEqual([(d.rule, d.severity) for d in login], [("login_after_failures", "critical")])
        self.assertIn("admin", login[0].title)

    def test_a_burst_early_in_a_long_batch_is_still_seen(self):
        two_hours_ago = timezone.now().timestamp() - 7200
        burst = [journald(f"Failed password for admin from 203.0.113.50 port {i} ssh2", date=two_hours_ago + i)
                 for i in range(10)]
        self.assertEqual([d.rule for d in self.ingest(burst + [journald("Started cron", program="CRON")])],
                         ["brute_force"])

    def test_password_spray_across_accounts(self):
        new = self.ingest([journald(f"Invalid user {name} from 198.51.100.7 port 1") for name in
                           ["oracle", "test", "guest", "ubuntu", "postgres"]])
        self.assertEqual({d.rule for d in new}, {"password_spray"})

    def test_single_event_rules(self):
        new = self.ingest([
            journald("Accepted publickey for root from 192.0.2.10 port 22 ssh2"),
            journald("add 'mallory' to group 'sudo'", program="usermod"),
            journald("new user: name=mallory, UID=1002, GID=1002", program="useradd"),
            journald("alice : user NOT in sudoers ; COMMAND=/bin/bash", program="sudo"),
        ])
        self.assertEqual(sorted(d.rule for d in new), ["account_created", "admin_added", "root_login", "sudo_denied"])
        windows_source = LogSource(organization=self.org, name="dc-01", os=LogSource.OS.WINDOWS)
        windows_source.issue_key()
        windows_source.save()
        wnew = analyze(windows_source, store(windows_source, [
            windows(1102, ["S-1-5", "attacker"]), windows(7045, message="A service was installed: evil"),
            *[failed_4625(user=f"user{i % 2}") for i in range(10)],
        ]))
        self.assertEqual(sorted(d.rule for d in wnew), ["brute_force", "logs_cleared", "service_installed"])
        self.assertEqual(LogDetection.objects.get(rule="logs_cleared").severity, "critical")

    def test_quiet_servers_are_flagged_once_and_cleared_when_they_return(self):
        store(self.source, [journald("hello")])
        LogSource.objects.filter(id=self.source.id).update(last_seen_at=timezone.now() - timedelta(hours=3))
        self.assertEqual([d.rule for d in check_silent_sources()], ["source_silent"])
        self.assertEqual(check_silent_sources(), [])
        self.source.refresh_from_db()
        self.assertEqual(self.source.status, "silent")
        store(self.source, [journald("back")])
        self.assertEqual(LogDetection.objects.get(rule="source_silent").status, "resolved")

    def test_new_detections_alert_through_the_existing_rules(self):
        NotificationRule.objects.create(organization=self.org, recipient_email="soc@acme.com", min_severity="high")
        NotificationRule.objects.create(organization=self.org, recipient_email="ceo@acme.com", min_severity="critical")
        source = self.source
        records = [journald(f"Failed password for admin from 203.0.113.9 port {i} ssh2") for i in range(10)]
        saved = store(source, records)
        analyze_events(str(source.id), saved[0].id, saved[-1].id)
        self.assertEqual([m.to for m in mail.outbox], [["soc@acme.com"]])
        self.assertIn("Many failed sign-ins from 203.0.113.9 on web-01", mail.outbox[0].subject)


class LogApiTests(LogFixture):
    def test_admins_connect_a_server_and_see_its_key_once(self):
        self.client.force_login(self.users["analyst"])
        body = {"organization": str(self.org.id), "name": "dc-01", "os": "windows"}
        self.assertEqual(self.client.post("/api/log-sources/", body, content_type=JSON).status_code, 403)
        self.client.force_login(self.users["admin"])
        response = self.client.post("/api/log-sources/", body, content_type=JSON)
        self.assertEqual(response.status_code, 201)
        key = response.json()["key"]
        self.assertTrue(key.startswith("dsl_"))
        self.assertTrue(response.json()["ingest_url"].endswith("/api/ingest/"))
        listed = self.client.get(f"/api/log-sources/?organization={self.org.id}").json()
        self.assertEqual({s["name"]: s["status"] for s in listed}, {"web-01": "waiting", "dc-01": "waiting"})
        self.assertNotIn("key", listed[0])
        self.assertEqual(self.client.post("/api/log-sources/", body, content_type=JSON).status_code, 400)  # same name

        replaced = self.client.post(f"/api/log-sources/{response.json()['id']}/replace-key/").json()["key"]
        self.client.logout()
        self.assertEqual(self.send([{"message": "x"}], key=key).status_code, 401)
        with patch("apps.logs.tasks.analyze_events.delay"):
            self.assertEqual(self.send([{"message": "x"}], key=replaced).status_code, 202)

    def test_members_search_and_outsiders_see_nothing(self):
        store(self.source, [journald("Failed password for admin from 203.0.113.9 port 1 ssh2"),
                            journald("Started cron", program="CRON")])
        self.client.force_login(self.users["viewer"])
        url = f"/api/log-events/?organization={self.org.id}"
        self.assertEqual(self.client.get(url).json()["count"], 2)
        self.assertEqual(self.client.get(url + "&category=auth_failure").json()["count"], 1)
        self.assertEqual(self.client.get(url + "&ip=203.0.113.9").json()["count"], 1)
        self.assertEqual(self.client.get(url + "&q=cron").json()["count"], 1)
        overview = self.client.get(f"/api/logs/overview/?organization={self.org.id}").json()
        self.assertEqual((overview["events_24h"], overview["failed_signins_24h"]), (2, 1))
        self.assertEqual(overview["top_attackers_24h"], [{"ip": "203.0.113.9", "failures": 1}])
        self.assertEqual(len(overview["rules"]), 17)

        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get("/api/log-events/").json()["count"], 0)
        self.assertEqual(self.client.get("/api/log-sources/").json(), [])
        self.assertEqual(self.client.get(f"/api/logs/overview/?organization={self.org.id}").status_code, 400)

    def test_analysts_resolve_detections(self):
        analyze(self.source, store(self.source, [journald("Accepted publickey for root from 192.0.2.1 port 1 ssh2")]))
        detection = LogDetection.objects.get()
        self.client.force_login(self.users["viewer"])
        self.assertEqual(self.client.post(f"/api/log-detections/{detection.id}/resolve/").status_code, 403)
        self.client.force_login(self.users["analyst"])
        analyze(self.source, store(self.source, [journald("new user: name=x", program="useradd")]))
        order = [d["severity"] for d in self.client.get(f"/api/log-detections/?organization={self.org.id}").json()["results"]]
        self.assertEqual(order, ["high", "medium"])  # worst first, though the medium is newer
        self.assertEqual(self.client.post(f"/api/log-detections/{detection.id}/resolve/").json()["status"], "resolved")
        open_url = f"/api/log-detections/?organization={self.org.id}&status=open"
        self.assertEqual(self.client.get(open_url).json()["count"], 1)

    def test_retention_and_deleting_the_organization(self):
        store(self.source, [journald("old"), journald("new")])
        LogEvent.objects.filter(message="old").update(occurred_at=timezone.now() - timedelta(days=40))
        purge_old_log_events()
        self.assertEqual(list(LogEvent.objects.values_list("message", flat=True)), ["new"])
        self.client.force_login(self.users["admin"])
        bad = self.client.patch(f"/api/organizations/{self.org.id}/", {"log_retention_days": 5}, content_type=JSON)
        self.assertEqual(bad.status_code, 400)
        ok = self.client.patch(f"/api/organizations/{self.org.id}/", {"log_retention_days": 90}, content_type=JSON)
        self.assertEqual(ok.json()["log_retention_days"], 90)
        removed = delete_organization(self.org)
        self.assertEqual((removed["log_events"], removed["log_sources"]), (1, 1))
