# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# Python version can be specified with `$ PYTHON_EXE=python3.x make conf`
PYTHON_EXE?=python3
VENV=venv
ACTIVATE?=. ${VENV}/bin/activate;

MANAGE=${VENV}/bin/python manage.py
VIRTUALENV_PYZ=etc/thirdparty/virtualenv.pyz
# Do not depend on Python to generate the SECRET_KEY
GET_SECRET_KEY=`base64 /dev/urandom | head -c50`
# Customize with `$ make envfile ENV_FILE=/etc/vulnerablecode/.env`
ENV_FILE=.env
# Customize with `$ make postgres VULNERABLECODE_DB_PASSWORD=YOUR_PASSWORD`
VULNERABLECODE_DB_PASSWORD=vulnerablecode

# Use sudo for postgres, but only on Linux
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
	SUDO_POSTGRES=sudo -u postgres
else
	SUDO_POSTGRES=
endif

ifeq ($(UNAME), Darwin)
	GET_SECRET_KEY=`head /dev/urandom | base64 | head -c50`
endif

virtualenv:
	@echo "-> Bootstrap the virtualenv with PYTHON_EXE=${PYTHON_EXE}"
	@${PYTHON_EXE} ${VIRTUALENV_PYZ} --never-download --no-periodic-update ${VENV}

conf: virtualenv
	@echo "-> Install dependencies"
	@${ACTIVATE} pip install -e . -c requirements.txt

dev: virtualenv
	@echo "-> Configure and install development dependencies"
	@${ACTIVATE} pip install -e .[dev] -c requirements.txt

envfile:
	@echo "-> Create the .env file and generate a secret key"
	@if test -f ${ENV_FILE}; then echo ".env file exists already"; exit 1; fi
	@mkdir -p $(shell dirname ${ENV_FILE}) && touch ${ENV_FILE}
	@echo SECRET_KEY=\"${GET_SECRET_KEY}\" > ${ENV_FILE}

migrate:
	@echo "-> Apply database migrations"
	${MANAGE} migrate

postgres:
	@echo "-> Configure PostgreSQL database"
	@echo "-> Create database user 'vulnerablecode'"
	${SUDO_POSTGRES} createuser --no-createrole --no-superuser --login --inherit --createdb vulnerablecode || true
	${SUDO_POSTGRES} psql -c "alter user vulnerablecode with encrypted password '${VULNERABLECODE_DB_PASSWORD}';" || true
	@echo "-> Drop 'vulnerablecode' database"
	${SUDO_POSTGRES} dropdb vulnerablecode || true
	@echo "-> Create 'vulnerablecode' database"
	${SUDO_POSTGRES} createdb --encoding=utf-8 --owner=vulnerablecode vulnerablecode
	@$(MAKE) migrate

sqlite:
	@echo "-> Configure SQLite database"
	@echo VULNERABLECODE_DB_ENGINE=\"django.db.backends.sqlite3\" >> ${ENV_FILE}
	@echo VULNERABLECODE_DB_NAME=\"sqlite3.db\" >> ${ENV_FILE}
	@$(MAKE) migrate

run:
	${MANAGE} runserver 8001 --insecure

bump:
	@echo "-> Bump the version"
	bin/bumpver update --no-fetch --patch

doc8:
	@echo "-> Run doc8 validation"
	@${ACTIVATE} doc8 --quiet docs/ *.rst

valid:
	@echo "-> Run Ruff format"
	@${ACTIVATE} ruff format
	@echo "-> Run Ruff linter"
	@${ACTIVATE} ruff check --fix

check:
	@echo "-> Run Ruff linter validation (pycodestyle, bandit, isort, and more)"
	@${ACTIVATE} ruff check
	@echo "-> Run Ruff format validation"
	@${ACTIVATE} ruff format --check
	@$(MAKE) doc8
	@echo "-> Run ABOUT files validation"
	@${ACTIVATE} about check etc/


clean:
	@echo "-> Clean the Python env"
	./configure --clean
	rm -rf ${VENV} build/ dist/ vulnerablecode.egg-info/ docs/_build/ pip-selfcheck.json
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete


test:
	@echo "-> Run the test suite"
	${ACTIVATE} ${PYTHON_EXE} -m pytest -vvs -m "not webtest"

webtest:
	@echo "-> Run web tests"
	${ACTIVATE} ${PYTHON_EXE} -m pytest -vvs -m "webtest"

docs:
	rm -rf docs/_build/
	@${ACTIVATE} sphinx-build docs/source docs/_build/

docs-check:
	@${ACTIVATE} sphinx-build -E -W -b html docs/source docs/_build/
	@${ACTIVATE} sphinx-build -E -W -b linkcheck docs/source docs/_build/

docker-images:
	@echo "-> Build Docker services"
	docker compose build
	@echo "-> Pull service images"
	docker compose pull
	@echo "-> Save the service images to a compressed tar archive in the dist/ directory"
	@mkdir -p dist/
	@docker save postgres vulnerablecode_vulnerablecode nginx | gzip > dist/vulnerablecode-images-`git describe --tags`.tar.gz

.PHONY: virtualenv conf dev envfile install check valid isort clean migrate postgres sqlite run test bump docs docker-images
