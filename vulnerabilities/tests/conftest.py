
import pytest
import os
import json


from vulnerabilities.api import PackageSerializer
from vulnerabilities.data_dump import debian_dump
from vulnerabilities.data_dump import ubuntu_dump
from vulnerabilities.data_dump import archlinux_dump
from vulnerabilities.scraper import archlinux
from vulnerabilities.scraper import debian
from vulnerabilities.scraper import ubuntu
from vulnerabilities.models import Package

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data/')


@pytest.fixture
def setDebianData(db):
    with open(os.path.join(TEST_DATA, 'debian.json')) as f:
        test_data = json.load(f)

    extract_data = debian.extract_vulnerabilities(test_data)
    debian_dump(extract_data)


@pytest.fixture
def setUbuntuData(db):
    with open(os.path.join(TEST_DATA, 'ubuntu_main.html')) as f:
        test_data = f.read()

    data = ubuntu.extract_cves(test_data)
    ubuntu_dump(data)


@pytest.fixture
def setArchLinuxData(db):
    with open(os.path.join(TEST_DATA, 'archlinux.json')) as f:
        test_data = json.load(f)

    archlinux_dump(test_data)
