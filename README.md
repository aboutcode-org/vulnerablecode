  

<div align="center">

<h1>VulnerableCode</h1>

  

[![Build Status](https://travis-ci.org/nexB/vulnerablecode.svg?branch=develop)](https://travis-ci.org/nexB/vulnerablecode)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[![Python 3.8](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/release/python-360/)

![stability-wip](https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg)

[![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/aboutcode-org/vulnerablecode)

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

  

![zz_comp](https://user-images.githubusercontent.com/28975399/89056138-2c8a8300-d379-11ea-882e-f28f38789cdc.png)

</div>

  
  
  

## The What

  

VulnerableCode is a FOSS database of vulnerabilities and the FOSS packages they impact. It is made by the FOSS community to improve and secure the open source software ecosystem.

  

## The Why

  

The existing solutions are commercial proprietary vulnerability databases, which in itself does not make sense because the data is about FOSS.

  

National Vulnerability Database which is the primary data source for all things security, is not particulary catered to address FOSS security issues, because:

  

1. It predates explosion of FOSS software usage

2. It's data format reflects commercial vendor-centric point of view, this is due to the usage of [CPE](https://nvd.nist.gov/products/cpe) to map vulnerabilities and the packages.

3. CPEs are just not designed to map FOSS to vulnerabilities owing to their vendor-product centric semantics. This makes it really hard to answer the fundamental question "Is package foo vulnerable to vulnerability bar?"

  

## The How

  

VulnerableCode independently aggregates many software vulnerability data sources that can easily be recreated in a decentralized fashion. These data sources include security advisories published by distros, package managers etc. Due to this the data obtained is not generalized to apply for other ecosystems. This increases the accuracy as the same version of a package across different distros may or may not be vulnerable to some vulnerability.

  

The packages are identified using [PURL](https://github.com/package-url/purl-spec) rather than CPEs. This makes it really easy to answer questions like "Is package foo vulnerable to vulnerability bar ? ".

  

The web interface enables community curation of data by enabling addition of new packages, vulnerabilities and modifying the relationships between them as shown in GIF. Along with the web interface the API allows seamless consumption of the data.

  

We also plan to mine for vulnerabilities which didn't receive any exposure due to various reasons like but not limited to the complicated procedure to receive CVE ID or not able to classify a bug as a security compromise. Check VulnerableCode at [Open Source Summit 2020](https://ossna2020.sched.com/event/c46p/why-is-there-no-free-software-vulnerability-database-philippe-ombredanne-aboutcodeorg-and-nexb-inc-michael-herzog-nexb-inc)

  
## Setting up VulnerableCode

Clone the source code:

```
git clone https://github.com/nexB/vulnerablecode.git
cd vulnerablecode
```


### Using Docker Compose

The easiest way to set up VulnerableCode is by using the docker containers.
For this you need to have the following installed.

- Docker Engine. Find instructions to install it [here](https://docs.docker.com/get-docker/)
- Docker Compose. Find instructions to install it [here](https://docs.docker.com/compose/install/#install-compose)

Use `sudo docker-compose up` to start VulnerableCode.

Access VulnerableCode at `http://localhost:8000/` or at `http://127.0.0.1:8000/` . 

Use `sudo docker-compose exec web bash` to access the VulnerableCode container. From  here you can run access `manage.py` and run management commands to import data as specified below. 

### Without docker
  

**System requirements**
  
- Python 3.8+

- PostgreSQL 9+ or [Docker](https://hub.docker.com/search/?type=edition&offering=community)

- Compiler toolchain and development files for Python and PostgreSQL

  

On Debian-based distros, these can be installed with `sudo apt install python3-venv python3-dev postgresql libpq-dev build-essential`. Leave out `postgresql` if you want to run it in Docker.

  

**Database configuration**


- Create a user named `vulnerablecode`. Use `vulnerablecode` as password when prompted:

`sudo -u postgres createuser --no-createrole --no-superuser --login --inherit --createdb --pwprompt vulnerablecode`
  

- Create a database named `vulnerablecode`:

`createdb --encoding=utf-8 --owner=vulnerablecode --user=vulnerablecode --password --host=localhost --port=5432 vulnerablecode`

  

**Application dependencies**

  

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

pycodestyle --exclude=migrations,settings.py,venv,lib_oval.py,test_ubuntu.py,test_suse.py,test_data_source.py --max-line-length=100 .

DJANGO_DEV=1 pytest

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

  

Start the web server.
  
In your browser access:  

```

http://127.0.0.1:8000/api/docs

```

For full documentation about API endpoints.