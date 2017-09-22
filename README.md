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
./manage.py migrate
```

Tests
-----

```
pycodestyle --exclude=migrations,settings.py,lib,tests --max-line-length=100 .
python3.6 -m pytest -v vulnerabilities/tests/test_scrapers.py vulnerabilities/tests/test_api_data.py 
```

For Django based tests
```
./manage.py test vulnerabilities/tests
```

Scrape and save to the database
-------------------------------

```
./manage.py shell
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
./manage.py runserver
```

In your browser access:
```
http://127.0.0.1:8000/vulnerabilities/api/<package_name>
```
