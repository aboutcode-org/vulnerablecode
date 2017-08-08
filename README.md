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
app/manage.py migrate
```

Tests
-----

```
pycodestyle --exclude=migrations,settings.py,lib,tests --max-line-length=100 .
cd app/
python3.6 -m pytest -v tests/
```

For Django based tests
```
cd app/
./manage.py test
```

Scrape and save to the database
-------------------------------

```
cd app/
./manage.py shell
```

```
from scraper import debian, ubuntu
from vulncode_app.data_dump import debian_dump, ubuntu_dump

debian_vulnerabilities = debian.scrape_vulnerabilities()
ubuntu_cves = ubuntu.scrape_cves()

debian_dump(debian_vulnerabilities)
ubuntu_dump(ubuntu_cves)
```
