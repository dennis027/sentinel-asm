# Ensures the Celery app is loaded whenever Django starts, so
# @shared_task decorators work anywhere in the codebase.
from .celery import app as celery_app

__all__ = ("celery_app",)
