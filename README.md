# ASM Platform

A lightweight attack surface management platform: subdomain discovery,
port scanning, SSL monitoring, and risk scoring, built on a Django +
Celery + Postgres + Redis stack.

This is the **week 0 skeleton** -- no scanning logic yet. Its only job
is to prove the stack boots cleanly end to end before any business
logic is added.

## Stack

| Service          | Role                                            |
|-------------------|-------------------------------------------------|
| `api`             | Django + DRF, served via `runserver` in dev      |
| `db`              | Postgres 16                                      |
| `redis`           | Celery broker/result backend + Django cache      |
| `celery-worker`   | Executes background tasks (scans, later)         |
| `celery-beat`     | Schedules periodic tasks (daily monitoring)      |

## Quickstart

```bash
cp .env.example .env
docker compose up --build
```

Then verify the stack:

```bash
curl http://localhost:8000/health/
# {"status": "ok", "checks": {"database": "ok", "redis": "ok"}}
```

If that returns `200` with both checks `"ok"`, the API can reach both
Postgres and Redis -- the whole stack is wired up correctly.

Run migrations (needed once Postgres is up):

```bash
docker compose exec api python manage.py migrate
docker compose exec api python manage.py createsuperuser
```

Admin panel: http://localhost:8000/admin/

## Verifying Celery is alive

```bash
docker compose exec api python manage.py shell -c \
  "from config.celery import debug_task; debug_task.delay()"
docker compose logs celery-worker --tail 20
```

You should see the task request logged by the worker.

## What's intentionally not here yet

- Scanner plugins (`apps/scanning/plugins/`) -- next milestone
- `nginx` reverse proxy and `flower` monitoring -- added once there's
  something worth reverse-proxying / monitoring
- Auth beyond Django's defaults -- JWT/RBAC comes with the API layer

## Architecture notes

- **One Dockerfile** builds `api`, `celery-worker`, and `celery-beat` --
  same codebase, different `command:`. Split into separate Dockerfiles
  once the worker image needs scanner binaries (nmap, nuclei, httpx)
  that the API image shouldn't carry.
- **Config is env-driven** (`django-environ`), so the same image runs
  in dev/CI/prod by swapping `.env` -- nothing is hardcoded in
  `settings.py`.
- **Redis serves two roles** (Celery broker/backend + Django cache)
  rather than running a second cache service -- not worth the extra
  container at this scale.
