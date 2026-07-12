from django.db import connections
from django.db.utils import OperationalError
from django.http import JsonResponse
import redis
from django.conf import settings


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
        {"status": "ok" if healthy else "unhealthy", "checks": checks},
        status=200 if healthy else 503,
    )


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
