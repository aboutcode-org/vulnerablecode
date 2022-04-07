import sys
import tempfile
from pathlib import Path

import environ

PROJECT_DIR = Path(__file__).resolve().parent
ROOT_DIR = PROJECT_DIR.parent

# Environment

ENV_FILE = "/etc/vulnerablecode/.env"
if not Path(ENV_FILE).exists():
    ENV_FILE = ROOT_DIR(".env")

env = environ.Env()
environ.Env.read_env(ENV_FILE)

# Security

SECRET_KEY = env.str("SECRET_KEY")

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[".localhost", "127.0.0.1", "[::1]"])

# SECURITY WARNING: don't run with debug turned on in production
DEBUG = env.bool("VULNERABLECODE_DEBUG", default=False)


# Application definition

INSTALLED_APPS = (
    # Local apps
    # Must come before Third-party apps for proper templates override
    "vulnerabilities",
    # Django built-in
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    # Third-party apps
    "django_filters",
    "rest_framework",
    "widget_tweaks",
)

MIDDLEWARE = (
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
)

ROOT_URLCONF = "vulnerablecode.urls"

WSGI_APPLICATION = "vulnerablecode.wsgi.application"


# Database

DATABASES = {
    "default": {
        "ENGINE": env.str("VULNERABLECODE_DB_ENGINE", "django.db.backends.postgresql"),
        "HOST": env.str("VULNERABLECODE_DB_HOST", "localhost"),
        "NAME": env.str("VULNERABLECODE_DB_NAME", "vulnerablecode"),
        "USER": env.str("VULNERABLECODE_DB_USER", "vulnerablecode"),
        "PASSWORD": env.str("VULNERABLECODE_DB_PASSWORD", "vulnerablecode"),
        "PORT": env.str("VULNERABLECODE_DB_PORT", "5432"),
        "ATOMIC_REQUESTS": True,
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# Templates

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [str(PROJECT_DIR.joinpath("templates"))],
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": DEBUG,
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.request",
                "django.template.context_processors.static",

            ],
        },
    },
]


# Passwords

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 14,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization

LANGUAGE_CODE = "en-us"

TIME_ZONE = env.str("TIME_ZONE", default="UTC")

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)

STATIC_URL = "/static/"
#STATIC_ROOT = "/var/vulnerablecode/static/"
STATIC_ROOT = env.str("VULNERABLECODE_STATIC_ROOT", "./")

STATICFILES_DIRS = [
    str(PROJECT_DIR.joinpath("static")),
]

# Third-party apps

# Django restframework

REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 100,
}

# Set this to true to enable community curation, ie users will be able to edit data
ENABLE_CURATION = False
