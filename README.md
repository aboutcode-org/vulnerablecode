# VulnerableCode

[![Build Status](https://travis-ci.org/nexB/vulnerablecode.svg?branch=develop)](https://travis-ci.org/nexB/vulnerablecode)

## Setup

Clone the source code:

```
git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
```

### System requirements

- Python 3.6+

- PostgreSQL 9+ or [Docker](https://hub.docker.com/search/?type=edition&offering=community)

- Compiler toolchain and development files for Python and PostgreSQL

On Debian-based distros, these can be installed with `sudo apt install python3-venv python3-dev postgresql libpq-dev build-essential`. Leave out `postgresql` if you want to run it in Docker.

### Database configuration

Either run PostgreSQL in Docker:
`docker run --name pg-vulnerablecode -e POSTGRES_USER=vulnerablecode -e POSTGRES_PASSWORD=vulnerablecode -e POSTGRES_DB=vulnerablecode -p 5432:5432 postgres`

Or without:

- Create a user named `vulnerablecode`. Use `vulnerablecode` as password when prompted:
  `sudo -u postgres createuser --no-createrole --no-superuser --login --inherit --createdb --pwprompt vulnerablecode`

- Create a databased named `vulnerablecode`:
  `createdb --encoding=utf-8 --owner=vulnerablecode  --user=vulnerablecode --password --host=localhost --port=5432 vulnerablecode`

### Application dependencies

Activate a virtualenv, install dependencies, and run the database migrations:

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
DJANGO_DEV=1 python manage.py migrate
```

The environment variable `DJANGO_DEV` is used to load settings suitable for development, defined in `vulnerablecode/dev.py`. If you don't want to type
it every time use `export DJANGO_DEV=1` instead.

When not running in development mode, an environment variable named `SECRET_KEY` needs to be set. The recommended way to generate this key is to use
the code Django includes for this purpose: `SECRET_KEY=$(python -c "from django.core.management import utils; print(utils.get_random_secret_key())")`.

## Tests

```
pycodestyle --exclude=migrations,settings.py,venv --max-line-length=100 .
python -m pytest -v importers/tests/test_scrapers.py api/tests/test_cve_search.py
```

For Django based tests
```
DJANGO_DEV=1 python manage.py test
```

## Data import

```
DJANGO_DEV=1 python manage.py import --all
```

If you want to run the import periodically, you can use a systemd timer:

```
$ cat ~/.config/systemd/user/vulnerablecode.service

[Unit]
Description=Update vulnerability database

[Service]
Type=oneshot
Environment="DJANGO_DEV=1"
ExecStart=/path/to/venv/bin/python /path/to/vulnerablecode/manage.py import --all

$ cat ~/.config/systemd/user/vulnerablecode.timer

[Unit]
Description=Periodically update vulnerability database

[Timer]
OnCalendar=daily

[Install]
WantedBy=multi-user.target
```

Start it with

```
systemctl --user daemon-reload && systemctl --user start vulnerablecode.timer
```

## API

Start the webserver

```
DJANGO_DEV=1 python manage.py runserver
```

In your browser access:

```
http://127.0.0.1:8000/api/
http://127.0.0.1:8000/api/packages/?name=<package_name>
```

## Deployment on Heroku

See https://devcenter.heroku.com/articles/django-app-configuration#creating-a-new-django-project
https://devcenter.heroku.com/articles/deploying-python#how-to-keep-build-artifacts-out-of-git

1. Create an Heroku account

2. Download and install the Heroku CLI https://devcenter.heroku.com/articles/heroku-cli#download-and-install

3. Run a local webserver: `heroku local web`

4. Login: `heroku login`

5. Create Heroku app: `heroku create`

6. Generate a secret key and pass it as an environment variable: `heroku config:set SECRET_KEY=$(python -c "from django.core.management import utils; print(utils.get_random_secret_key())")`

7. Deploy: `git push heroku <branch>:master`

8. Migrate the database: `heroku run python manage.py migrate`

9. Load the data referring to chapter "Data import" above.

10. To check the logs: `heroku logs --tail`

### Periodic Data Import

Note: Running jobs with Heroku Scheduler might incur costs. If you haven't already, you need to add a credit card in your account (https://dashboard.heroku.com/account/billing).

1. Install the Scheduler add-on: `heroku addons:create scheduler:standard`

2. Open the Scheduler dashboard: `heroku addons:open scheduler`

3. Click on "Create job" and enter `python manage.py import --all` under "Run Command"
