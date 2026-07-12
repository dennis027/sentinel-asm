"""
Celery application entrypoint.

Import this in config/__init__.py so `django-admin` / `manage.py` and
worker processes share the same app instance.

Queue routing note (for future scanning tasks): route CPU/IO-heavy
scanners to "discovery" or "scanning" queues and lightweight tasks to
"reporting", so a slow nmap sweep can never starve report generation.
Example, once scanning tasks exist:

    CELERY_TASK_ROUTES = {
        "apps.scanning.tasks.run_discovery": {"queue": "discovery"},
        "apps.scanning.tasks.run_port_scan": {"queue": "scanning"},
        "apps.reports.tasks.generate_report": {"queue": "reporting"},
    }
"""

import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("asm_platform")

# Read CELERY_* settings from Django settings.py (namespaced so they
# don't collide with Django's own settings).
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-discover tasks.py in every INSTALLED_APPS app.
app.autodiscover_tasks()


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Sanity-check task: run via `python manage.py shell` ->
    from config.celery import debug_task; debug_task.delay()
    then check the worker logs for the request repr.
    """
    print(f"Request: {self.request!r}")
