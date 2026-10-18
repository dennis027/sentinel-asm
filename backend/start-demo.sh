#!/bin/sh
# Everything in one container, for a free demo deployment (render.yaml):
# migrations, the admin user and demo data, then the Celery worker (with
# the daily schedule built in) in the background and gunicorn in front.
# A real deployment runs these as separate services instead
# (render.production.yaml, docker-compose.prod.yml).
set -e

python manage.py migrate --noinput
python manage.py setup_periodic_tasks
python manage.py collectstatic --noinput -v0

# The first user, from DJANGO_SUPERUSER_USERNAME / _EMAIL / _PASSWORD
# (there is no shell on Render's free plan). Already there: nothing to do.
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
  python manage.py createsuperuser --noinput 2>/dev/null || echo "Admin user already exists."
  # The demo company (Acme Retail). The container's disk is wiped on every
  # restart, so it is reloaded each time to bring its screenshots back.
  if [ "${DEMO_DATA:-true}" = "true" ]; then
    python manage.py load_demo_data --owner "$DJANGO_SUPERUSER_USERNAME" --reset
  fi
fi

# One worker process at a time, with beat inside it: the free instance has 512 MB.
celery -A config worker --beat --loglevel=info --concurrency=1 \
  --scheduler django_celery_beat.schedulers:DatabaseScheduler &

exec gunicorn config.wsgi:application --bind "0.0.0.0:${PORT:-8000}" --workers 2 --timeout 90 --access-logfile -
