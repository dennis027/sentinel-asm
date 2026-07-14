import importlib
import pkgutil

from django.apps import AppConfig


class ScanningConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.scanning"

    def ready(self):
        """
        Auto-import every module under plugins/ so each one's
        @register_scanner decorator runs and populates the registry.
        This means adding a new scanner is purely "drop a file in
        plugins/" -- no import list to maintain here or anywhere else.
        """
        from . import plugins

        for _, module_name, _ in pkgutil.iter_modules(plugins.__path__):
            if module_name in ("base", "registry"):
                continue
            importlib.import_module(f"{plugins.__name__}.{module_name}")