from django.apps import AppConfig


class AuditLogsConfig(AppConfig):
    name = 'apps.audit_logs'

    def ready(self):
        from . import signals  # noqa: F401  -- registers the receiver