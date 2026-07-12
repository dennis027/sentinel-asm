# Shared image for django-api, celery-worker, and celery-beat.
# They're the same codebase/dependencies -- only the CMD differs per
# service in docker-compose.yml. When scanner binaries (nmap, nuclei,
# httpx) are added later, split this into Dockerfile.api / Dockerfile.worker
# so the API image doesn't carry tools it never uses.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps needed to build psycopg2-binary and friends
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
