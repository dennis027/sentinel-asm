"""
Django settings for the ASM platform.

All environment-specific values (secrets, hosts, DB, redis) come from
environment variables so the same image runs in dev, CI, and prod --
only the .env / compose config changes.
"""

from datetime import timedelta
from pathlib import Path

import environ
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
)
# Reads a .env file if present (local dev without Docker). In Docker,
# env vars are injected directly by docker-compose, so this is a no-op there.
environ.Env.read_env(BASE_DIR / ".env")

# Secure by default: DEBUG is off unless the environment turns it on
# (.env.example does, for local dev), and outside DEBUG there is no
# fallback SECRET_KEY -- a deploy that forgot to set one refuses to
# start instead of quietly signing sessions and JWTs with a public key.
DEBUG = env.bool("DJANGO_DEBUG", default=False)

_INSECURE_DEV_SECRET_KEY = "dev-only-insecure-key-change-me"
SECRET_KEY = env("DJANGO_SECRET_KEY", default=_INSECURE_DEV_SECRET_KEY if DEBUG else "")
if not SECRET_KEY:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is off.")

ALLOWED_HOSTS = env.list(
    "DJANGO_ALLOWED_HOSTS", default=["*"] if DEBUG else ["localhost", "127.0.0.1"]
)

# How many trusted reverse proxies sit in front of the API. 0 (default)
# means X-Forwarded-For is client-controlled and is ignored -- both for
# the login throttle (DRF reads this via REST_FRAMEWORK["NUM_PROXIES"])
# and for the IPs written to the auth audit log. Set to 1 behind the
# bundled nginx (docker-compose.prod.yml does).
NUM_PROXIES = env.int("NUM_PROXIES", default=0)

# Set when the site is served over HTTPS (directly or via a
# TLS-terminating proxy that sends X-Forwarded-Proto).
if env.bool("DJANGO_HTTPS", default=False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 60 * 60 * 24 * 30

CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# Bearer token Prometheus must present to scrape /metrics. Unset: the
# endpoint only works in DEBUG. See config/metrics.py.
METRICS_TOKEN = env("METRICS_TOKEN", default="")


# ---- Scan safety -------------------------------------------------------

# Organizations must prove they control their root domain (DNS TXT
# record, see Organization.verification_record_*) before anything can
# be scanned. On by default outside DEBUG; turn off only for a private
# lab where every user is trusted.
REQUIRE_DOMAIN_VERIFICATION = env.bool("ASM_REQUIRE_DOMAIN_VERIFICATION", default=not DEBUG)

# Refuse targets that resolve to loopback/private/link-local addresses
# (see apps/scanning/targets.py). Only enable for scanning your own
# internal network on purpose.
ALLOW_PRIVATE_SCAN_TARGETS = env.bool("ASM_ALLOW_PRIVATE_SCAN_TARGETS", default=False)

# Remediation SLA: how many days after a finding first appears it
# should be fixed, by severity. Drives the "fix by" dates, the overdue
# count and the weekly report. Info findings have no deadline.
REMEDIATION_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}

# How many pages the screenshot scanner captures per asset: the landing
# page plus the pages it links to on the same host. 1 = landing page only.
SCREENSHOT_MAX_PAGES = env.int("ASM_SCREENSHOT_MAX_PAGES", default=6)

# A scan job still unfinished after this long is assumed dead and
# marked failed by reap_stale_scan_jobs. Must stay above
# CELERY_TASK_TIME_LIMIT below.
SCAN_JOB_STALE_AFTER_MINUTES = env.int("ASM_SCAN_JOB_STALE_AFTER_MINUTES", default=30)


# ---- Applications -----------------------------------------------------

INSTALLED_APPS = [
    "django_prometheus",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "django_filters",
    "drf_spectacular",    
    "django_celery_beat",
    "health",
    "apps.organizations",
    "apps.assets",
    "apps.scanning",
    "apps.findings",
    "apps.notifications",
    "apps.api",
    "apps.audit_logs",
]

MIDDLEWARE = [
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware", 
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# ---- Database -----------------------------------------------------------
# Points at the "db" service name from docker-compose.yml, not localhost.

DATABASES = {
    "default": env.db(
        "DATABASE_URL",
        default="postgres://asm_user:asm_password@db:5432/asm_platform",
    )
}


# ---- Cache / Celery broker -----------------------------------------------
# Redis does double duty: Django cache backend AND Celery broker/result
# backend (configured separately in config/celery.py).

REDIS_URL = env("REDIS_URL", default="redis://redis:6379/0")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
    }
}


# ---- Auth / DRF -----------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        # JWT first -- this is what the Angular frontend actually uses.
        # Session/Basic stay enabled too: Session keeps the browsable API
        # and /admin/ working, Basic keeps curl/script testing simple.
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        # Read-only keys for integrations (Authorization: Api-Key ...).
        "apps.api.authentication.ApiKeyAuthentication",
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "config.pagination.DefaultPagination",
    "PAGE_SIZE": 25,
    "NUM_PROXIES": NUM_PROXIES,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    # Brute-force protection on login: 5 attempts per minute per IP.
    # Scoped specifically to LoginView (throttle_scope="login") rather
    # than a blanket rate on every endpoint.
    "DEFAULT_THROTTLE_RATES": {
        "login": "5/min",
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Densight API",
    "DESCRIPTION": "Attack surface management: assets, scan jobs, and findings.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    # Finding.Severity choices get reused on NotificationRule.min_severity
    # under a different field name -- without this override,
    # drf-spectacular generates two differently-named enums for what's
    # actually the same choice set.
    "ENUM_NAME_OVERRIDES": {
        "MinSeverityEnum": "apps.findings.models.Finding.Severity",
        # Both models have a field called "status" with different choices.
        "FindingStatusEnum": "apps.findings.models.Finding.Status",
        "ScanJobStatusEnum": "apps.scanning.models.ScanJob.Status",
    },
}

# ---- i18n / static --------------------------------------------------------

SIMPLE_JWT = {
    # Short-lived access token (sent on every request) + longer refresh
    # token (used only to mint new access tokens) -- standard JWT
    # pattern, limits the damage window if an access token leaks.
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

# CORS: the Angular dev server runs on a different origin (port 4200)
# than this API (port 8000) -- browsers block that by default unless
# the server explicitly allows it. Configurable via env so prod can
# point at the real deployed frontend URL instead of localhost.
CORS_ALLOWED_ORIGINS = env.list(
    "CORS_ALLOWED_ORIGINS", default=["http://localhost:4200"]  
)

# Email: console backend by default -- notification emails print to the
# celery-worker container's logs instead of needing a real mailbox, so
# this is fully testable locally with zero SMTP setup. Set EMAIL_BACKEND
# and the SMTP settings via env when a real mail provider is wired up.
EMAIL_HOST = env("EMAIL_HOST", default="")
EMAIL_PORT = env.int("EMAIL_PORT", default=587)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")   
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=True)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="alerts@densight.local")

EMAIL_BACKEND = env(
    "EMAIL_BACKEND",
    default=(
        "django.core.mail.backends.smtp.EmailBackend"
        if EMAIL_HOST
        else "django.core.mail.backends.console.EmailBackend"
    ),
)

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
  
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"  


DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---- Logging -----------------------------------------------------------
# Every log line -> one JSON object, so log aggregators (CloudWatch,
# Datadog, Loki, ...) can actually query/alert on fields instead of
# grepping free text. See config/logging_utils.py for the formatter.

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {"()": "config.logging_utils.JsonFormatter"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "json"},
    },
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "django": {"handlers": ["console"], "level": "INFO", "propagate": False},
        # Quiets routine per-request access logs (still JSON, just less
        # noisy than Django's default) -- errors/warnings still surface.
        "django.server": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "celery": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "apps": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}



# ---- Celery -----------------------------------------------------------
# Broker and result backend both point at Redis. Task routing is where
# you'll assign scanner tasks to queues (discovery/scanning/reporting)
# as they're added -- see config/celery.py for the pattern.

CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
# Hard ceiling on any single task. The slowest scanner (nuclei) gives
# its subprocess 10 minutes; the soft limit raises inside the task so
# the job is recorded as failed/retrying, the hard limit kills a task
# that ignores it.
CELERY_TASK_SOFT_TIME_LIMIT = 14 * 60
CELERY_TASK_TIME_LIMIT = 15 * 60
CELERY_TASK_ROUTES = {}  # populated as scanning/reports tasks are added
# DatabaseScheduler stores periodic task definitions in Postgres (via
# django_celery_beat) rather than a static dict in this settings file --
# means schedules are viewable/editable in /admin/ without a redeploy.
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"


