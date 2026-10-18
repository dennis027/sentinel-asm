import os

import redis
from django.conf import settings
from django.db import connections
from django.db.utils import OperationalError
from django.http import JsonResponse


def health_check(request):
    """
    GET /health/

    Verifies the API can reach both Postgres and Redis. This is the
    first endpoint to hit after `docker compose up` -- if this returns
    200 with both checks "ok", the whole stack (api, db, redis) is wired
    up correctly.
    """
    checks = {"database": _check_database(), "redis": _check_redis()}
    healthy = all(v == "ok" for v in checks.values())
    return JsonResponse(
        # Which commit is running (Render sets RENDER_GIT_COMMIT): the deploy
        # pipeline waits for it to match what it just deployed.
        {"status": "ok" if healthy else "unhealthy", "checks": checks, "version": _version()},
        status=200 if healthy else 503,
    )


def _version():
    return os.environ.get("RENDER_GIT_COMMIT") or os.environ.get("GIT_COMMIT") or "unknown"


def _check_database():
    try:
        connections["default"].cursor()
        return "ok"
    except OperationalError as exc:
        return f"error: {exc}"


def _check_redis():
    try:
        client = redis.from_url(settings.REDIS_URL)
        client.ping()
        return "ok"
    except Exception as exc:
        return f"error: {exc}"
