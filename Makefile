# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.
# Modified for VulnerableCode use

# Python version can be specified with `$ PYTHON_EXE=python3.x make conf`
PYTHON_EXE?=python3
VENV=venv
ACTIVATE?=. ${VENV}/bin/activate;
VIRTUALENV_PYZ=etc/thirdparty/virtualenv.pyz
BLACK_ARGS=-l 100 .
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

virtualenv:
	@echo "-> Bootstrap the virtualenv with PYTHON_EXE=${PYTHON_EXE}"
	@${PYTHON_EXE} ${VIRTUALENV_PYZ} --never-download --no-periodic-update ${VENV}

conf: virtualenv
	@echo "-> Install dependencies"
	@${ACTIVATE} pip install -r requirements.txt

dev: conf
	@echo "-> Configure and install development dependencies"
	@${ACTIVATE} pip install -r requirements-dev.txt

envfile:
	@echo "-> Create the .env file and generate a secret key"
	@if test -f ${ENV_FILE}; then echo ".env file exists already"; exit 1; fi
	@mkdir -p $(shell dirname ${ENV_FILE}) && touch ${ENV_FILE}
	@echo SECRET_KEY=\"${GET_SECRET_KEY}\" > ${ENV_FILE}

check:
	@echo "-> Run black validation"
	@${ACTIVATE} black --check ${BLACK_ARGS}

black:
	@echo "-> Apply black code formatter"
	${VENV}/bin/black ${BLACK_ARGS}

valid: black

clean:
	@echo "-> Clean the Python env"
	rm -rm ${VENV}

migrate:
	@echo "-> Apply database migrations"
	${ACTIVATE} ./manage.py migrate

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
	${ACTIVATE} ./manage.py runserver

test:
	@echo "-> Run offline tests"
	${ACTIVATE} ${PYTHON_EXE} -m pytest -v -m "not webtest"

webtest:
	@echo "-> Run web tests"
	${ACTIVATE} ${PYTHON_EXE} -m pytest -v -m "webtest"

package: conf
	@echo "-> Create a VulnerableCode package for offline installation"
	@echo "-> Fetch dependencies in thirdparty/ for offline installation"
	rm -rf thirdparty && mkdir thirdparty
	${VENV}/bin/pip download -r requirements.txt --no-cache-dir --dest thirdparty
	@echo "-> Create package in dist/ for offline installation"
	${VENV}/bin/python setup.py sdist

install: virtualenv
	@echo "-> Install and configure the Python env with base dependencies, offline"
	${VENV}/bin/pip install --upgrade --no-index --no-cache-dir --find-links=thirdparty -e .

.PHONY: virtualenv conf dev envfile install check valid clean migrate postgres sqlite run test package
