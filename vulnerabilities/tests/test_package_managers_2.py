import json
import os
from datetime import datetime
from unittest import mock

import pytest
import pytz

from vulnerabilities.package_managers_2 import GoproxyVersionAPI
from vulnerabilities.package_managers_2 import LegacyVersion
from vulnerabilities.package_managers_2 import NugetVersionAPI
from vulnerabilities.package_managers_2 import PypiVersionAPI
from vulnerabilities.package_managers_2 import RubyVersionAPI

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "package_manager_data")


@pytest.mark.parametrize(
    "url_path", ["https://pkg.go.dev/https://github.com/xx/a/b", "https://github.com/xx/a/b"]
)
def test_trim_go_url_path(url_path):
    assert GoproxyVersionAPI.trim_go_url_path(url_path) == "github.com/xx/a"


def test_trim_go_url_path_failure(caplog):
    url_path = "https://github.com"
    assert GoproxyVersionAPI.trim_go_url_path(url_path) == None
    assert "Not a valid Go URL path" in caplog.text


def test_nuget_extract_version():
    with open(os.path.join(TEST_DATA, "nuget-data.json"), "r") as f:
        resp = json.load(f)
    assert NugetVersionAPI.extract_versions(resp) == {
        LegacyVersion(
            value="3.0.3", release_date=datetime(2011, 11, 27, 13, 50, 2, 63000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="3.0.5", release_date=datetime(2011, 12, 12, 12, 0, 25, 947000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="2.1.0", release_date=datetime(2011, 1, 22, 13, 34, 8, 550000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="3.0.0", release_date=datetime(2011, 11, 24, 0, 26, 2, 527000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="3.0.4", release_date=datetime(2011, 12, 12, 10, 18, 33, 380000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="3.0.6", release_date=datetime(2012, 1, 2, 21, 10, 43, 403000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="3.4.0", release_date=datetime(2013, 10, 20, 13, 32, 30, 837000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="3.4.1", release_date=datetime(2014, 1, 17, 9, 17, 43, 680000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="3.5.0-beta3",
            release_date=datetime(2015, 1, 6, 17, 39, 25, 147000, tzinfo=pytz.UTC),
        ),
        LegacyVersion(
            value="3.5.0-beta2",
            release_date=datetime(2015, 1, 1, 14, 9, 28, 710000, tzinfo=pytz.UTC),
        ),
        LegacyVersion(
            value="3.5.0", release_date=datetime(2015, 1, 14, 2, 1, 58, 853000, tzinfo=pytz.UTC)
        ),
        LegacyVersion(
            value="3.5.1", release_date=datetime(2015, 1, 23, 1, 5, 44, 447000, tzinfo=pytz.UTC)
        ),
    }


def test_nuget_extract_version_with_illformed_data():
    assert NugetVersionAPI.extract_versions({"items": [{"items": [{"catalogEntry": {}}]}]}) == set()


@mock.patch("vulnerabilities.package_managers_2.get_response")
def test_pypi_fetch_data(mock_response):
    pypi_api = PypiVersionAPI()
    with open(os.path.join(TEST_DATA, "pypi.json"), "r") as f:
        mock_response.return_value = json.load(f)
    pypi_api.fetch("django")
    assert pypi_api.cache == {
        "django": {
            LegacyVersion(
                value="1.10.5",
                release_date=datetime(2017, 1, 4, 19, 23, 0, 596664, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10.8",
                release_date=datetime(2017, 9, 5, 15, 31, 58, 221021, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10rc1",
                release_date=datetime(2016, 7, 18, 18, 5, 5, 503584, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10.4",
                release_date=datetime(2016, 12, 1, 23, 46, 50, 215935, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10a1",
                release_date=datetime(2016, 5, 20, 12, 24, 59, 952686, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10.3",
                release_date=datetime(2016, 11, 1, 13, 57, 16, 55061, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10.1",
                release_date=datetime(2016, 9, 1, 23, 18, 18, 672706, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10.2",
                release_date=datetime(2016, 10, 1, 20, 5, 31, 330942, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10.7",
                release_date=datetime(2017, 4, 4, 14, 27, 54, 235551, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10.6",
                release_date=datetime(2017, 3, 1, 13, 37, 40, 243134, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.1.4",
                release_date=datetime(2011, 2, 9, 4, 13, 7, 75, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10b1",
                release_date=datetime(2016, 6, 22, 1, 15, 17, 267637, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.1.3",
                release_date=datetime(2010, 12, 23, 5, 14, 23, 509436, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="1.10",
                release_date=datetime(2016, 8, 1, 18, 32, 16, 280614, tzinfo=pytz.UTC),
            ),
        }
    }


@mock.patch("vulnerabilities.package_managers_2.get_response")
def test_pypi_fetch_with_no_release(mock_response):
    pypi_api = PypiVersionAPI()
    mock_response.return_value = {"info": {}}
    pypi_api.fetch("django")
    assert pypi_api.cache == {"django": set()}


@mock.patch("vulnerabilities.package_managers_2.get_response")
def test_pypi_fetch_with_no_release(mock_response):
    ruby_api = RubyVersionAPI()
    with open(os.path.join(TEST_DATA, "gem.json"), "r") as f:
        mock_response.return_value = json.load(f)
    ruby_api.fetch("rails")
    assert ruby_api.cache == {
        "rails": {
            LegacyVersion(
                value="7.0.2.3",
                release_date=datetime(2022, 3, 8, 17, 50, 52, 496000, tzinfo=pytz.UTC),
            ),
            LegacyVersion(
                value="7.0.2.2",
                release_date=datetime(2022, 2, 11, 19, 44, 19, 17000, tzinfo=pytz.UTC),
            ),
        }
    }
