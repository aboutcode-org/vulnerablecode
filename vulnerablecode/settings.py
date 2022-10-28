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

from vulnerablecode import __version__

VULNERABLECODE_VERSION = __version__

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

VULNERABLECODE_REQUIRE_AUTHENTICATION = env.bool(
    "VULNERABLECODE_REQUIRE_AUTHENTICATION", default=False
)

VULNERABLECODE_PASSWORD_MIN_LENGTH = env.int("VULNERABLECODE_PASSWORD_MIN_LENGTH", default=14)

# SECURITY WARNING: do not run with debug turned on in production
DEBUG = env.bool("VULNERABLECODE_DEBUG", default=False)

# SECURITY WARNING: do not  run with debug turned on in production
DEBUG_TOOLBAR = env.bool("VULNERABLECODE_DEBUG_TOOLBAR", default=False)

# SECURITY WARNING: do not  run with debug turned on in production
DEBUG_UI = env.bool("VULNERABLECODE_DEBUG_UI", default=False)

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = env.str("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env.str("EMAIL_HOST_PASSWORD", default="")

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
    "crispy_forms",
    # for API doc
    "drf_spectacular",
    # required for Django collectstatic discovery
    "drf_spectacular_sidecar",
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
            "min_length": VULNERABLECODE_PASSWORD_MIN_LENGTH,
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

REST_FRAMEWORK_DEFAULT_THROTTLE_RATES = {
    "vulnerable_packages": "1/hour",
    "bulk_search_packages": "5/hour",
    "packages": "10/minute",
    "vulnerabilities": "10/minute",
    "aliases": "5/minute",
    "cpes": "5/minute",
    "bulk_search_cpes": "5/hour",
}

if IS_TESTS:
    VULNERABLECODEIO_REQUIRE_AUTHENTICATION = True
    REST_FRAMEWORK_DEFAULT_THROTTLE_RATES = {
        "vulnerable_packages": "1/day",
        "bulk_search_packages": "6/day",
        "packages": "10/day",
        "vulnerabilities": "8/day",
        "aliases": "2/day",
        "cpes": "4/day",
        "bulk_search_cpes": "5/day",
    }


USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)

STATIC_URL = "/static/"
# STATIC_ROOT = "/var/vulnerablecode/static/"
STATIC_ROOT = env.str("VULNERABLECODE_STATIC_ROOT", "./")

STATICFILES_DIRS = [
    str(PROJECT_DIR / "static"),
]


CRISPY_TEMPLATE_PACK = "bootstrap4"

# Third-party apps

# Django restframework

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("rest_framework.authentication.TokenAuthentication",),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
        "rest_framework.renderers.AdminRenderer",
    ),
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ),
    "DEFAULT_THROTTLE_CLASSES": [
        "vulnerabilities.throttling.StaffUserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": REST_FRAMEWORK_DEFAULT_THROTTLE_RATES,
    "DEFAULT_PAGINATION_CLASS": "vulnerabilities.pagination.SmallResultSetPagination",
    # Limit the load on the Database returning a small number of records by default. https://github.com/nexB/vulnerablecode/issues/819
    "PAGE_SIZE": 10,
    # for API docs
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

api_doc_intro = """
<div>
    <p><strong>VulnerableCode</strong> is open data and free software by
    <a href="https://github.com/nexB/vulnerablecode"> nexB Inc. and others.</a>
    </p>
    <p>The VulnerableCode API exposes these endpoints:</p>
    <ul>
        <li>
            <strong>packages/</strong>: main endpoint to lookup for vulnerable packages.
        </li>
        <li>
            <strong>vulnerabilities/</strong>: secondary endpoint to lookup by vulnerabilities.
        </li>
        <li>
            <strong>alias/</strong>: secondary endpoint to lookup vulnerabilities by aliases (e.g., CVE)
        </li>
        <li>
            <strong>cpes/</strong>: secondary endpoint to lookup vulnerabilities by CPE.
        </li>
    </ul>
</div>
"""

# for API docs
SPECTACULAR_SETTINGS = {
    "TITLE": "VulnerableCode API",
    "DESCRIPTION": api_doc_intro,
    "VERSION": VULNERABLECODE_VERSION,
    "TOS": "/tos/",
    "CONTACT": {
        "name": "nexB Inc.",
        "url": "https://public.vulnerablecode.io",
        "email": "mailto:info@nexb.com",
    },
    "LICENSE": {
        "name": "Source code: Apache-2.0 | Data: CC-BY-SA-4.0",
        "url": "https://github.com/nexb/vulnerablecode#license",
    },
    "SERVE_INCLUDE_SCHEMA": False,
    # shorthand to use the sidecar instead
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "/static/images/favicon.ico",
    # See https://swagger.io/docs/open-source-tools/swagger-ui/usage/configuration/
    "SWAGGER_UI_SETTINGS": {
        "deepLinking": True,
        "displayOperationId": True,
        "defaultModelsExpandDepth": 1,
        "displayRequestDuration": True,
        "docExpansion": "list",
    },
    "SORT_OPERATIONS": False,
    "TAGS_SORTER": False,
}

if DEBUG_TOOLBAR:
    INSTALLED_APPS += ("debug_toolbar",)

    MIDDLEWARE += ("debug_toolbar.middleware.DebugToolbarMiddleware",)

    DEBUG_TOOLBAR_PANELS = (
        "debug_toolbar.panels.history.HistoryPanel",
        "debug_toolbar.panels.versions.VersionsPanel",
        "debug_toolbar.panels.timer.TimerPanel",
        "debug_toolbar.panels.settings.SettingsPanel",
        "debug_toolbar.panels.headers.HeadersPanel",
        "debug_toolbar.panels.request.RequestPanel",
        "debug_toolbar.panels.sql.SQLPanel",
        "debug_toolbar.panels.staticfiles.StaticFilesPanel",
        "debug_toolbar.panels.templates.TemplatesPanel",
        "debug_toolbar.panels.cache.CachePanel",
        "debug_toolbar.panels.signals.SignalsPanel",
        "debug_toolbar.panels.logging.LoggingPanel",
        "debug_toolbar.panels.redirects.RedirectsPanel",
        "debug_toolbar.panels.profiling.ProfilingPanel",
    )

    INTERNAL_IPS = [
        "127.0.0.1",
    ]

if not VULNERABLECODEIO_REQUIRE_AUTHENTICATION:
    REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] = ("rest_framework.permissions.AllowAny",)
