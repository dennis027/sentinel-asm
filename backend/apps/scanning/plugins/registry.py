"""
Central lookup from scanner_name (a plain string stored on ScanJob) to
the BaseScanner subclass that implements it.

Registration happens via decorator, and the registry is populated at
Django startup by ScanningConfig.ready() auto-importing every module in
plugins/ -- see apps/scanning/apps.py. This means adding a scanner is
strictly additive: new file + decorator, nothing else changes.
"""

from .base import BaseScanner

_REGISTRY: dict[str, type[BaseScanner]] = {}


def register_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    if not getattr(cls, "name", None):
        raise ValueError(f"{cls.__name__} must set a `name` class attribute")
    if cls.name in _REGISTRY:
        raise ValueError(f"Scanner name '{cls.name}' is already registered")
    _REGISTRY[cls.name] = cls
    return cls


def get_scanner(name: str) -> type[BaseScanner]:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ValueError(
            f"No scanner registered as '{name}'. Registered: {list(_REGISTRY)}"
        )


def list_scanners() -> list[str]:
    return sorted(_REGISTRY.keys())