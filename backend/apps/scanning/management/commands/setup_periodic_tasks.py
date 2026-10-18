"""
Creates (or updates) the periodic tasks in the database: the daily
monitoring run, the stale-scan-job reaper, the daily risk snapshot,
the end of time-limited risk acceptances and the Monday weekly report.

Run once after deploying: `python manage.py setup_periodic_tasks`.
Safe to re-run -- uses get_or_create/update, never duplicates the
schedule entry.
"""

from django.core.management.base import BaseCommand
from django_celery_beat.models import CrontabSchedule, IntervalSchedule, PeriodicTask


class Command(BaseCommand):
    help = "Set up the daily scan schedule and stale-job reaper for celery-beat."

    REAP_EVERY_MINUTES = 10

    def add_arguments(self, parser):
        parser.add_argument(
            "--hour", type=int, default=2,
            help="UTC hour to run daily scans (default: 2am UTC, off-peak).",
        )

    def handle(self, *args, **options):
        hour = options["hour"]

        schedule, _ = CrontabSchedule.objects.get_or_create(
            minute="0", hour=str(hour), day_of_week="*", day_of_month="*", month_of_year="*",
        )

        task, created = PeriodicTask.objects.update_or_create(
            name="daily-asm-scans",
            defaults=dict(
                crontab=schedule,
                task="apps.scanning.tasks.trigger_daily_scans",
                enabled=True,
            ),
        )

        verb = "Created" if created else "Updated"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} periodic task '{task.name}' -> runs daily at {hour:02d}:00 UTC."
        ))

        interval, _ = IntervalSchedule.objects.get_or_create(
            every=self.REAP_EVERY_MINUTES, period=IntervalSchedule.MINUTES,
        )
        reaper, created = PeriodicTask.objects.update_or_create(
            name="reap-stale-scan-jobs",
            defaults=dict(
                interval=interval,
                crontab=None,
                task="apps.scanning.tasks.reap_stale_scan_jobs",
                enabled=True,
            ),
        )
        verb = "Created" if created else "Updated"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} periodic task '{reaper.name}' -> runs every {self.REAP_EVERY_MINUTES} minutes."
        ))

        log_check = PeriodicTask.objects.update_or_create(
            name="check-log-sources",
            defaults=dict(interval=interval, crontab=None, task="apps.logs.tasks.check_log_sources", enabled=True),
        )[0]
        self.stdout.write(self.style.SUCCESS(
            f"Set up periodic task '{log_check.name}' -> runs every {self.REAP_EVERY_MINUTES} minutes."
        ))

        snapshots, _ = CrontabSchedule.objects.get_or_create(
            minute="30", hour="23", day_of_week="*", day_of_month="*", month_of_year="*",
        )
        weekly, _ = CrontabSchedule.objects.get_or_create(
            minute="0", hour="7", day_of_week="1", day_of_month="*", month_of_year="*",
        )
        for name, task_path, crontab, when in [
            ("record-risk-snapshots", "apps.findings.tasks.record_risk_snapshots", snapshots, "daily at 23:30 UTC"),
            ("send-weekly-reports", "apps.notifications.tasks.send_weekly_reports", weekly, "Mondays at 07:00 UTC"),
            ("expire-risk-acceptances", "apps.findings.tasks.expire_risk_acceptances", snapshots, "daily at 23:30 UTC"),
            ("purge-old-log-events", "apps.logs.tasks.purge_old_log_events", snapshots, "daily at 23:30 UTC"),
            ("sync-known-exploited", "apps.findings.tasks.sync_known_exploited", schedule, f"daily at {hour:02d}:00 UTC"),
        ]:
            task, created = PeriodicTask.objects.update_or_create(
                name=name, defaults=dict(crontab=crontab, interval=None, task=task_path, enabled=True),
            )
            verb = "Created" if created else "Updated"
            self.stdout.write(self.style.SUCCESS(f"{verb} periodic task '{task.name}' -> runs {when}."))
