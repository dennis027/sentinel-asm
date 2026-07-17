"""
Django settings for the ASM platform.

All environment-specific values (secrets, hosts, DB, redis) come from
environment variables so the same image runs in dev, CI, and prod --
only the .env / compose config changes.
"""

from pathlib import Path
import environ
from datetime import timedelta  

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
)
# Reads a .env file if present (local dev without Docker). In Docker,
# env vars are injected directly by docker-compose, so this is a no-op there.
environ.Env.read_env(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", default="dev-only-insecure-key-change-me")
DEBUG = env("DJANGO_DEBUG", default=True)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["*"])


# ---- Applications -----------------------------------------------------

INSTALLED_APPS = [
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
    "apps.api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware", 
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
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
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "ASM Platform API",
    "DESCRIPTION": "Attack surface management: assets, scan jobs, and findings.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
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



LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


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
CELERY_TASK_ROUTES = {}  # populated as scanning/reports tasks are added
# DatabaseScheduler stores periodic task definitions in Postgres (via
# django_celery_beat) rather than a static dict in this settings file --
# means schedules are viewable/editable in /admin/ without a redeploy.
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"

