import json
import os
from datetime import datetime

import pytest
import pytz

from vulnerabilities.package_managers_2 import GoproxyVersionAPI
from vulnerabilities.package_managers_2 import LegacyVersion
from vulnerabilities.package_managers_2 import NugetVersionAPI

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
