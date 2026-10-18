"""Where each scan came from, and Scan history grouped by it."""

import importlib
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.apps import apps as django_apps
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from apps.assets.models import Asset
from apps.audit_logs.models import ActivityEvent
from apps.findings.models import Finding
from apps.organizations.models import Membership, Organization
from apps.scanning.models import ScanJob
from apps.scanning.tasks import fan_out_domain_scan, trigger_daily_scans

T = ScanJob.Trigger


class OriginFixture(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", root_domain="acme.com",
                                               domain_verified_at=timezone.now())
        self.analyst = User.objects.create_user("amina", password="pass12345!", first_name="Amina", last_name="Otieno")
        Membership.objects.create(user=self.analyst, organization=self.org, role="analyst")
        self.shop = Asset.objects.create(organization=self.org, value="shop.acme.com", asset_type=Asset.AssetType.SUBDOMAIN)
        self.www = Asset.objects.create(organization=self.org, value="www.acme.com", asset_type=Asset.AssetType.SUBDOMAIN)
        self.client.force_login(self.analyst)

    def trigger(self, **body):
        with patch("apps.api.views.run_scan_job.delay"), patch("apps.api.views.fan_out_domain_scan.delay") as fan_out:
            response = self.client.post("/api/scan-jobs/trigger/", body, content_type="application/json")
        return response, fan_out


class TriggerTests(OriginFixture):
    def test_single_scans_and_rechecks_record_who_and_group_together(self):
        response, _ = self.trigger(scanner_name="ssl_expiry", asset_id=str(self.www.id), force=True)
        single = ScanJob.objects.get(id=response.json()["id"])
        self.assertEqual((single.trigger, single.triggered_by), (T.SINGLE, self.analyst))
        self.assertEqual(response.json()["triggered_by"], "Amina Otieno")

        run = str(uuid.uuid4())
        for scanner in ("httpx", "nmap", "ssl_expiry"):
            self.trigger(scanner_name=scanner, asset_id=str(self.shop.id), force=True, run_id=run, reason="recheck")
        recheck = ScanJob.objects.filter(asset=self.shop)
        self.assertEqual(set(recheck.values_list("trigger", "run_id")), {(T.RECHECK, uuid.UUID(run))})

        # Someone else's run id can't be borrowed: the scan gets its own.
        response, _ = self.trigger(scanner_name="nmap", asset_id=str(self.www.id), force=True, run_id=str(single.run_id),
                                   reason="recheck")
        self.assertNotEqual(response.json()["run_id"], str(single.run_id))

    def test_run_scan_for_the_domain(self):
        response, fan_out = self.trigger(scanner_name="nmap", organization_id=str(self.org.id))
        self.assertEqual(response.status_code, 202)
        args = fan_out.call_args.args
        self.assertEqual(args[3], self.analyst.id)
        with patch("apps.scanning.tasks.run_scan_job.delay"):
            fan_out_domain_scan(*args)
        jobs = ScanJob.objects.filter(scanner_name="nmap")
        self.assertEqual(jobs.count(), 2)
        self.assertEqual(set(jobs.values_list("trigger", "triggered_by", "run_id")),
                         {(T.DOMAIN, self.analyst.id, uuid.UUID(response.json()["batch_id"]))})

    def test_the_daily_schedule_is_one_run_per_organization_per_day(self):
        with patch("apps.scanning.tasks.run_scan_job.delay"):
            trigger_daily_scans()
            trigger_daily_scans()  # beat firing twice: nothing doubled
        jobs = ScanJob.objects.filter(organization=self.org)
        self.assertGreater(jobs.count(), 10)
        self.assertEqual(set(jobs.values_list("trigger", "triggered_by", "run_id")),
                         {(T.SCHEDULE, None, ScanJob.schedule_run_id(self.org.id))})


class RunsTests(OriginFixture):
    def job(self, run, trigger, scanner, asset, status=ScanJob.Status.SUCCESS, who=None, minutes_ago=0):
        job = ScanJob.objects.create(organization=self.org, asset=asset, scanner_name=scanner, trigger=trigger,
                                     run_id=run, triggered_by=who, status=status,
                                     idempotency_key=uuid.uuid4().hex,
                                     finished_at=None if status == ScanJob.Status.RUNNING else timezone.now())
        ScanJob.objects.filter(id=job.id).update(created_at=timezone.now() - timedelta(minutes=minutes_ago))
        return job

    def test_history_grouped_by_where_it_came_from(self):
        night, click, recheck = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        for scanner in ("nmap", "httpx"):
            for asset in (self.shop, self.www):
                self.job(night, T.SCHEDULE, scanner, asset, minutes_ago=600)
        self.job(night, T.SCHEDULE, "email_security", None, status=ScanJob.Status.FAILED, minutes_ago=600)
        self.job(click, T.DOMAIN, "nmap", self.shop, who=self.analyst, minutes_ago=60)
        self.job(click, T.DOMAIN, "nmap", self.www, status=ScanJob.Status.RUNNING, who=self.analyst, minutes_ago=60)
        found = self.job(recheck, T.RECHECK, "httpx", self.shop, who=self.analyst, minutes_ago=5)
        self.job(recheck, T.RECHECK, "nmap", self.shop, who=self.analyst, minutes_ago=5)
        Finding.objects.create(asset=self.shop, scan_job=found, finding_type="missing_header", severity="low",
                               title="Missing HSTS", dedupe_key="x")

        base = f"/api/scan-jobs/runs/?organization={self.org.id}"
        runs = self.client.get(base).json()["results"]
        self.assertEqual([r["trigger"] for r in runs], ["recheck", "domain", "schedule"])
        recheck_run, click_run, night_run = runs
        self.assertEqual((recheck_run["host"], recheck_run["scanners"], recheck_run["triggered_by"], recheck_run["new_findings"]),
                         ("shop.acme.com", 2, "Amina Otieno", 1))
        self.assertEqual((click_run["scanner_label"], click_run["hosts"], click_run["unfinished"], click_run["finished"]),
                         ("Port scan", 2, 1, None))
        self.assertEqual((night_run["jobs"], night_run["failed"], night_run["hosts"], night_run["organization_level"],
                          night_run["triggered_by"], night_run["scanner_name"]), (5, 1, 2, True, None, None))

        self.assertEqual([r["trigger"] for r in self.client.get(base + "&status=running").json()["results"]], ["domain"])
        self.assertEqual([r["trigger"] for r in self.client.get(base + "&status=failed").json()["results"]], ["schedule"])
        self.assertEqual([r["trigger"] for r in self.client.get(base + "&trigger=schedule").json()["results"]], ["schedule"])
        # A run's own scans.
        jobs = self.client.get(f"/api/scan-jobs/?organization={self.org.id}&run_id={click}").json()
        self.assertEqual(jobs["count"], 2)
        self.assertEqual(self.client.get("/api/scan-jobs/runs/").status_code, 400)

    def test_other_organizations_runs_never_show(self):
        other = Organization.objects.create(name="Other", root_domain="other.com")
        ScanJob.objects.create(organization=other, scanner_name="nmap", idempotency_key="o", trigger=T.SCHEDULE)
        self.assertEqual(self.client.get(f"/api/scan-jobs/runs/?organization={other.id}").json()["count"], 0)


class BackfillTests(OriginFixture):
    def test_past_scans_are_sorted_out_by_how_they_were_created(self):
        migration = importlib.import_module("apps.scanning.migrations.0006_scanjob_run_id_scanjob_trigger_scanjob_triggered_by")
        start = timezone.now() - timedelta(days=1)

        def old(scanner, asset, seconds, batch=None):
            job = ScanJob.objects.create(organization=self.org, asset=asset, scanner_name=scanner, batch_id=batch,
                                         idempotency_key=uuid.uuid4().hex)
            ScanJob.objects.filter(id=job.id).update(created_at=start + timedelta(seconds=seconds))
            return job.id

        night = [old("nmap", self.shop, 0), old("nmap", self.www, 5), old("security_txt", None, 9)]
        batch = uuid.uuid4()
        clicked = [old("httpx", self.shop, 3600, batch), old("httpx", self.www, 3601, batch)]
        recheck = [old("httpx", self.shop, 7200), old("nmap", self.shop, 7201)]
        single = old("ssl_expiry", self.www, 9000)
        event = ActivityEvent.objects.create(organization=self.org, actor=self.analyst, actor_name="Amina",
                                             verb="scan_started", summary="Started Open ports")
        ActivityEvent.objects.filter(id=event.id).update(created_at=start + timedelta(seconds=7230))

        migration.backfill(django_apps, None)

        def info(ids):
            return set(ScanJob.objects.filter(id__in=ids).values_list("trigger", "run_id", "triggered_by"))

        self.assertEqual(info(night), {(T.SCHEDULE, ScanJob.schedule_run_id(self.org.id, start.date()), None)})
        self.assertEqual(info(clicked), {(T.DOMAIN, batch, None)})
        ((trigger, run, who),) = info(recheck)
        self.assertEqual((trigger, who), (T.RECHECK, self.analyst.id))
        self.assertEqual(ScanJob.objects.get(id=single).trigger, T.SINGLE)
        self.assertEqual(ScanJob.objects.values("run_id").distinct().count(), 4)
