#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import sys
from pathlib import Path

import environ

PROJECT_DIR = Path(__file__).resolve().parent
ROOT_DIR = PROJECT_DIR.parent

# Environment

ENV_FILE = "/etc/vulnerablecode/.env"
if not Path(ENV_FILE).exists():
    ENV_FILE = ROOT_DIR / ".env"

env = environ.Env()
environ.Env.read_env(str(ENV_FILE))

# Security

SECRET_KEY = env.str("SECRET_KEY")

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[".localhost", "127.0.0.1", "[::1]"])

# SECURITY WARNING: don't run with debug turned on in production
DEBUG = env.bool("VULNERABLECODE_DEBUG", default=False)

# SECURITY WARNING: don't run with debug turned on in production
DEBUG_UI = env.bool("VULNERABLECODE_DEBUG_UI", default=False)

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
    "django.contrib.humanize",
    # Third-party apps
    "django_filters",
    "rest_framework",
    "rest_framework.authtoken",
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
                "vulnerablecode.context_processors.versions",
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

IS_TESTS = False

if len(sys.argv) > 0:
    IS_TESTS = "pytest" in sys.argv[0]

VULNERABLECODEIO_REQUIRE_AUTHENTICATION = env.bool(
    "VULNERABLECODEIO_REQUIRE_AUTHENTICATION", default=False
)

LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

if IS_TESTS:
    VULNERABLECODEIO_REQUIRE_AUTHENTICATION = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)

STATIC_URL = "/static/"
# STATIC_ROOT = "/var/vulnerablecode/static/"
STATIC_ROOT = env.str("VULNERABLECODE_STATIC_ROOT", "./")

STATICFILES_DIRS = [
    str(PROJECT_DIR / "static"),
]

# Third-party apps

# Django restframework

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("rest_framework.authentication.TokenAuthentication",),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
        #    "rest_framework.renderers.AdminRenderer",
    ),
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ),
    "DEFAULT_PAGINATION_CLASS": "vulnerabilities.pagination.SmallResultSetPagination",
    # Limit the load on the Database returning a small number of records by default. https://github.com/nexB/vulnerablecode/issues/819
    "PAGE_SIZE": 10,
}

if not VULNERABLECODEIO_REQUIRE_AUTHENTICATION:
    REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] = ("rest_framework.permissions.AllowAny",)
