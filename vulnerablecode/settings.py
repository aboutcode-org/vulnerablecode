from pathlib import Path

import environ

PROJECT_DIR = Path(__file__).resolve().parent
ROOT_DIR = PROJECT_DIR.parent

# Environment

env_file = str(ROOT_DIR.joinpath(".env"))
if Path(env_file).exists():
    environ.Env.read_env(env_file)

env = environ.Env(TRAVIS=(bool, False))

SECRET_KEY = env.str("SECRET_KEY")

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[".localhost", "127.0.0.1", "[::1]"])
DEBUG = True

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "vulnerabilities",
    "rest_framework",
    "django_filters",
    "widget_tweaks",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "vulnerablecode.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [str(PROJECT_DIR.joinpath("templates"))],
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": False,
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.static",
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "vulnerablecode.wsgi.application"


# Database

DATABASES = {
    "default": {
        "ENGINE": env.str("VULNERABLECODE_DB_ENGINE", "django.db.backends.postgresql"),
        "NAME": env.str("VULNERABLECODE_DB_NAME", "vulnerablecode"),
        "USER": env.str("VULNERABLECODE_DB_USER", "vulnerablecode"),
        "PASSWORD": env.str("VULNERABLECODE_DB_PASSWORD", "vulnerablecode"),
        "HOST": env.str("VULNERABLECODE_DB_HOST", "localhost"),
        "PORT": env.str("VULNERABLECODE_DB_PORT", "5432"),
    }
}

if env("TRAVIS"):
    DATABASES["default"]["USER"] = "postgres"
    DATABASES["default"]["PASSWORD"] = ""

# Django 3.2 compat stuff
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
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

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)

STATIC_URL = "/static/"
STATIC_ROOT = "./"

STATICFILES_DIRS = [
    str(PROJECT_DIR.joinpath("static")),
]

# REST API
REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": ("django_filters.rest_framework.DjangoFilterBackend",),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 100,
}

# Set this to true to enable community curation, ie users will be able to edit data
ENABLE_CURATION = False
