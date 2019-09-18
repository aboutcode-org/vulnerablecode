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
python manage.py migrate
```

## Tests

```
pycodestyle --exclude=migrations,settings.py,venv,tests --max-line-length=100 .
python -m pytest -v vulnerabilities/tests/test_scrapers.py vulnerabilities/tests/test_api_data.py
```

For Django based tests
```
python manage.py test vulnerabilities/tests
```

## Data import

```
python manage.py shell
```

```
from vulnerabilities.scraper import archlinux, debian, ubuntu
from vulnerabilities.data_dump import archlinux_dump, debian_dump, ubuntu_dump

# May be needed on macOS
# import ssl; ssl._create_default_https_context = ssl._create_unverified_context

ubuntu_cves = ubuntu.scrape_cves()
ubuntu_dump(ubuntu_cves)

debian_vulnerabilities = debian.scrape_vulnerabilities()
debian_dump(debian_vulnerabilities)

archlinux_vulnerabilities = archlinux.scrape_vulnerabilities()
archlinux_dump(archlinux_vulnerabilities)
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

6. Deploy: `git push heroku <branch>:master`

7. Migrate the database: `heroku run python manage.py migrate`

8. Load the data referring to chapter "Data import" above.

9. To check the logs: `heroku logs --tail`
