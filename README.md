# VulnerableCode

[![Build Status](https://travis-ci.org/nexB/vulnerablecode.svg?branch=develop)](https://travis-ci.org/nexB/vulnerablecode)

Setup
-----
VulnerableCode requires Python 3.6+, get the latest version at https://www.python.org/

Clone the source code:

```
git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
```

Activate a virtualenv, install dependencies, and run the database migrations:

```
python3.6 -m venv .
source bin/activate
pip install -r requirements.txt
DJANGO_DEV=1 >> .env
DJANGO_DEV=1 ./manage.py migrate
```

Tests
-----

```
pycodestyle --exclude=migrations,settings.py,lib,tests --max-line-length=100 .
python3.6 -m pytest -v vulnerabilities/tests/test_scrapers.py vulnerabilities/tests/test_api_data.py 
```

For Django based tests
```
DJANGO_DEV=1 ./manage.py test vulnerabilities/tests
```

Scrape and save to the database
-------------------------------

```
DJANGO_DEV=1 ./manage.py shell
```

```
from vulnerabilities.scraper import debian, ubuntu
from vulnerabilities.data_dump import debian_dump, ubuntu_dump

# May be needed on macOS
# import ssl; ssl._create_default_https_context = ssl._create_unverified_context

ubuntu_cves = ubuntu.scrape_cves()
ubuntu_dump(ubuntu_cves)

debian_vulnerabilities = debian.scrape_vulnerabilities()
debian_dump(debian_vulnerabilities)
```

API
----
Start the webserver

```
DJANGO_DEV=1 ./manage.py runserver
```

In your browser access:
```
http://127.0.0.1:8000/vulnerabilities/api/<package_name>
```

Deployment on Heroku
--------------------

See https://devcenter.heroku.com/articles/django-app-configuration#creating-a-new-django-project
https://devcenter.heroku.com/articles/deploying-python#how-to-keep-build-artifacts-out-of-git

1. Create an Heroku account

2. Download and install the Heroku CLI https://devcenter.heroku.com/articles/heroku-cli#download-and-install

3. Run a local webserver: `heroku local web`

4. Login: `heroku login`

5. Create Heroku app: `heroku create`

6. Deploy: `git push heroku <branch>:master`

7. Migrate the database: `heroku run python manage.py migrate`

8. Load the data referring to chapter "Scrape and save to the database" above.

9. To check the logs: `heroku logs --tail`
