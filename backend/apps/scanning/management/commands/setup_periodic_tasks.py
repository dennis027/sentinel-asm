"""
Creates (or updates) the daily monitoring schedule in the database.

Run once after deploying: `python manage.py setup_periodic_tasks`.
Safe to re-run -- uses get_or_create/update, never duplicates the
schedule entry.
"""

from django.core.management.base import BaseCommand
from django_celery_beat.models import CrontabSchedule, PeriodicTask


class Command(BaseCommand):
    help = "Set up the daily scan schedule for celery-beat."

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