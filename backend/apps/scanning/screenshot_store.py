"""
Where screenshot images live: Django's default storage, which is the
disk (MEDIA_ROOT) under docker compose and S3-compatible object storage
(Cloudflare R2, S3) when S3_BUCKET is set -- so the worker that takes
a screenshot and the API that shows it don't need to share a disk.

Paths are always "screenshots/<asset id>/<file>.png", relative to the
storage; findings keep that path in raw_data["screenshot_path"].
"""

import posixpath

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage

ROOT = "screenshots"


def path_for(asset_id, filename: str) -> str:
    return f"{ROOT}/{asset_id}/{filename}"


def save(relative_path: str, data: bytes) -> str:
    """Stores the PNG; returns the path it was stored under (the storage may rename a clash)."""
    return default_storage.save(relative_path, ContentFile(data))


def safe(relative_path) -> str | None:
    """The path if it is a screenshot path (no "..", no absolute path), else None."""
    if not isinstance(relative_path, str) or not relative_path:
        return None
    normalized = posixpath.normpath(relative_path)
    if normalized.startswith("/") or not normalized.startswith(f"{ROOT}/") or ".." in normalized.split("/"):
        return None
    return normalized


def open_image(relative_path):
    """An open file for a stored screenshot, or None when it isn't there."""
    path = safe(relative_path)
    if path is None or not default_storage.exists(path):
        return None
    return default_storage.open(path, "rb")


def delete_for_asset(asset_id) -> int:
    """Removes every screenshot of an asset; returns how many files were deleted."""
    folder = f"{ROOT}/{asset_id}"
    try:
        _, files = default_storage.listdir(folder)
    except (FileNotFoundError, OSError):
        return 0
    for name in files:
        default_storage.delete(f"{folder}/{name}")
    # On disk the now-empty folder stays behind; harmless, but tidy it.
    if hasattr(default_storage, "path"):
        try:
            import os

            os.rmdir(default_storage.path(folder))
        except OSError:
            pass
    return len(files)
