#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from datetime import datetime
from functools import partial
from unittest import mock

import pytest
from dateutil.tz import tzlocal

from vulnerabilities.package_managers import ComposerVersionAPI
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import GoproxyVersionAPI
from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.package_managers import NugetVersionAPI
from vulnerabilities.package_managers import PackageVersion
from vulnerabilities.package_managers import PypiVersionAPI
from vulnerabilities.package_managers import RubyVersionAPI
from vulnerabilities.package_managers import VersionResponse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "package_manager_data")

dt_local = partial(datetime, tzinfo=tzlocal())


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
        response = json.load(f)
    results = list(NugetVersionAPI().extract_versions(response))
    expected = [
        PackageVersion(value="2.1.0", release_date=dt_local(2011, 1, 22, 13, 34, 8, 550000)),
        PackageVersion(value="3.0.0", release_date=dt_local(2011, 11, 24, 0, 26, 2, 527000)),
        PackageVersion(value="3.0.3", release_date=dt_local(2011, 11, 27, 13, 50, 2, 63000)),
        PackageVersion(value="3.0.4", release_date=dt_local(2011, 12, 12, 10, 18, 33, 380000)),
        PackageVersion(value="3.0.5", release_date=dt_local(2011, 12, 12, 12, 0, 25, 947000)),
        PackageVersion(value="3.0.6", release_date=dt_local(2012, 1, 2, 21, 10, 43, 403000)),
        PackageVersion(value="3.4.0", release_date=dt_local(2013, 10, 20, 13, 32, 30, 837000)),
        PackageVersion(value="3.4.1", release_date=dt_local(2014, 1, 17, 9, 17, 43, 680000)),
        PackageVersion(value="3.5.0-beta2", release_date=dt_local(2015, 1, 1, 14, 9, 28, 710000)),
        PackageVersion(value="3.5.0-beta3", release_date=dt_local(2015, 1, 6, 17, 39, 25, 147000)),
        PackageVersion(value="3.5.0", release_date=dt_local(2015, 1, 14, 2, 1, 58, 853000)),
        PackageVersion(value="3.5.1", release_date=dt_local(2015, 1, 23, 1, 5, 44, 447000)),
    ]
    assert results == expected


def test_nuget_extract_version_with_illformed_data():
    test_data = {"items": [{"items": [{"catalogEntry": {}}]}]}
    results = list(NugetVersionAPI.extract_versions(test_data))
    assert results == []


@mock.patch("vulnerabilities.package_managers.get_response")
def test_pypi_fetch_data(mock_response):
    pypi_api = PypiVersionAPI()
    with open(os.path.join(TEST_DATA, "pypi.json"), "r") as f:
        mock_response.return_value = json.load(f)

    results = list(pypi_api.fetch("django"))
    expected = [
        PackageVersion(value="1.1.3", release_date=dt_local(2010, 12, 23, 5, 14, 23, 509436)),
        PackageVersion(value="1.1.4", release_date=dt_local(2011, 2, 9, 4, 13, 7, 75)),
        PackageVersion(value="1.10", release_date=dt_local(2016, 8, 1, 18, 32, 16, 280614)),
        PackageVersion(value="1.10.1", release_date=dt_local(2016, 9, 1, 23, 18, 18, 672706)),
        PackageVersion(value="1.10.2", release_date=dt_local(2016, 10, 1, 20, 5, 31, 330942)),
        PackageVersion(value="1.10.3", release_date=dt_local(2016, 11, 1, 13, 57, 16, 55061)),
        PackageVersion(value="1.10.4", release_date=dt_local(2016, 12, 1, 23, 46, 50, 215935)),
        PackageVersion(value="1.10.5", release_date=dt_local(2017, 1, 4, 19, 23, 0, 596664)),
        PackageVersion(value="1.10.6", release_date=dt_local(2017, 3, 1, 13, 37, 40, 243134)),
        PackageVersion(value="1.10.7", release_date=dt_local(2017, 4, 4, 14, 27, 54, 235551)),
        PackageVersion(value="1.10.8", release_date=dt_local(2017, 9, 5, 15, 31, 58, 221021)),
        PackageVersion(value="1.10a1", release_date=dt_local(2016, 5, 20, 12, 24, 59, 952686)),
        PackageVersion(value="1.10b1", release_date=dt_local(2016, 6, 22, 1, 15, 17, 267637)),
        PackageVersion(value="1.10rc1", release_date=dt_local(2016, 7, 18, 18, 5, 5, 503584)),
    ]
    assert results == expected


@mock.patch("vulnerabilities.package_managers.get_response")
def test_pypi_fetch_with_no_release(mock_response):
    mock_response.return_value = {"info": {}}
    results = list(PypiVersionAPI().fetch("django"))
    assert results == []


@mock.patch("vulnerabilities.package_managers.get_response")
def test_ruby_fetch_with_no_release(mock_response):

    with open(os.path.join(TEST_DATA, "gem.json")) as f:
        mock_response.return_value = json.load(f)

    results = list(RubyVersionAPI().fetch("rails"))

    expected = [
        PackageVersion(value="7.0.2.3", release_date=dt_local(2022, 3, 8, 17, 50, 52, 496000)),
        PackageVersion(value="7.0.2.2", release_date=dt_local(2022, 2, 11, 19, 44, 19, 17000)),
    ]

    assert results == expected


class TestComposerVersionAPI:

    expected_versions = [
        PackageVersion(value=("10.0.0",), release_date=dt_local(2019, 7, 23, 7, 6, 3)),
        PackageVersion(value=("10.1.0",), release_date=dt_local(2019, 10, 1, 8, 18, 18)),
        PackageVersion(value=("10.2.0",), release_date=dt_local(2019, 12, 3, 11, 16, 26)),
        PackageVersion(value=("10.2.1",), release_date=dt_local(2019, 12, 17, 11, 0)),
        PackageVersion(value=("10.2.2",), release_date=dt_local(2019, 12, 17, 11, 36, 14)),
        PackageVersion(value=("10.3.0",), release_date=dt_local(2020, 2, 25, 12, 50, 9)),
        PackageVersion(value=("10.4.0",), release_date=dt_local(2020, 4, 21, 8, 0, 15)),
        PackageVersion(value=("10.4.1",), release_date=dt_local(2020, 4, 28, 9, 7, 54)),
        PackageVersion(value=("10.4.2",), release_date=dt_local(2020, 5, 12, 10, 41, 40)),
        PackageVersion(value=("10.4.3",), release_date=dt_local(2020, 5, 19, 13, 16, 31)),
        PackageVersion(value=("10.4.4",), release_date=dt_local(2020, 6, 9, 8, 56, 30)),
        PackageVersion(value=("8.7.10",), release_date=dt_local(2018, 2, 6, 10, 46, 2)),
        PackageVersion(value=("8.7.11",), release_date=dt_local(2018, 3, 13, 12, 44, 45)),
        PackageVersion(value=("8.7.12",), release_date=dt_local(2018, 3, 22, 11, 35, 42)),
        PackageVersion(value=("8.7.13",), release_date=dt_local(2018, 4, 17, 8, 15, 46)),
        PackageVersion(value=("8.7.14",), release_date=dt_local(2018, 5, 22, 13, 51, 9)),
        PackageVersion(value=("8.7.15",), release_date=dt_local(2018, 5, 23, 11, 31, 21)),
        PackageVersion(value=("8.7.16",), release_date=dt_local(2018, 6, 11, 17, 18, 14)),
        PackageVersion(value=("8.7.17",), release_date=dt_local(2018, 7, 12, 11, 29, 19)),
        PackageVersion(value=("8.7.18",), release_date=dt_local(2018, 7, 31, 8, 15, 29)),
        PackageVersion(value=("8.7.19",), release_date=dt_local(2018, 8, 21, 7, 23, 21)),
        PackageVersion(value=("8.7.20",), release_date=dt_local(2018, 10, 30, 10, 39, 51)),
        PackageVersion(value=("8.7.21",), release_date=dt_local(2018, 12, 11, 12, 40, 12)),
        PackageVersion(value=("8.7.22",), release_date=dt_local(2018, 12, 14, 7, 43, 50)),
        PackageVersion(value=("8.7.23",), release_date=dt_local(2019, 1, 22, 10, 10, 2)),
        PackageVersion(value=("8.7.24",), release_date=dt_local(2019, 1, 22, 15, 25, 55)),
        PackageVersion(value=("8.7.25",), release_date=dt_local(2019, 5, 7, 10, 5, 55)),
        PackageVersion(value=("8.7.26",), release_date=dt_local(2019, 5, 15, 11, 24, 12)),
        PackageVersion(value=("8.7.27",), release_date=dt_local(2019, 6, 25, 8, 24, 21)),
        PackageVersion(value=("8.7.28",), release_date=dt_local(2019, 10, 15, 7, 21, 52)),
        PackageVersion(value=("8.7.29",), release_date=dt_local(2019, 10, 30, 21, 0, 45)),
        PackageVersion(value=("8.7.30",), release_date=dt_local(2019, 12, 17, 10, 49, 17)),
        PackageVersion(value=("8.7.31",), release_date=dt_local(2020, 2, 17, 23, 29, 16)),
        PackageVersion(value=("8.7.32",), release_date=dt_local(2020, 3, 31, 8, 33, 3)),
        PackageVersion(value=("8.7.7",), release_date=dt_local(2017, 9, 19, 14, 22, 53)),
        PackageVersion(value=("8.7.8",), release_date=dt_local(2017, 10, 10, 16, 8, 44)),
        PackageVersion(value=("8.7.9",), release_date=dt_local(2017, 12, 12, 16, 9, 50)),
        PackageVersion(value=("9.0.0",), release_date=dt_local(2017, 12, 12, 16, 48, 22)),
        PackageVersion(value=("9.1.0",), release_date=dt_local(2018, 1, 30, 15, 31, 12)),
        PackageVersion(value=("9.2.0",), release_date=dt_local(2018, 4, 9, 20, 51, 35)),
        PackageVersion(value=("9.2.1",), release_date=dt_local(2018, 5, 22, 13, 47, 11)),
        PackageVersion(value=("9.3.0",), release_date=dt_local(2018, 6, 11, 17, 14, 33)),
        PackageVersion(value=("9.3.1",), release_date=dt_local(2018, 7, 12, 11, 33, 12)),
        PackageVersion(value=("9.3.2",), release_date=dt_local(2018, 7, 12, 15, 51, 49)),
        PackageVersion(value=("9.3.3",), release_date=dt_local(2018, 7, 31, 8, 20, 17)),
        PackageVersion(value=("9.4.0",), release_date=dt_local(2018, 9, 4, 12, 8, 20)),
        PackageVersion(value=("9.5.0",), release_date=dt_local(2018, 10, 2, 8, 10, 33)),
        PackageVersion(value=("9.5.1",), release_date=dt_local(2018, 10, 30, 10, 45, 30)),
        PackageVersion(value=("9.5.10",), release_date=dt_local(2019, 10, 15, 7, 29, 55)),
        PackageVersion(value=("9.5.11",), release_date=dt_local(2019, 10, 30, 20, 46, 49)),
        PackageVersion(value=("9.5.12",), release_date=dt_local(2019, 12, 17, 10, 53, 45)),
        PackageVersion(value=("9.5.13",), release_date=dt_local(2019, 12, 17, 14, 17, 37)),
        PackageVersion(value=("9.5.14",), release_date=dt_local(2020, 2, 17, 23, 37, 2)),
        PackageVersion(value=("9.5.15",), release_date=dt_local(2020, 3, 31, 8, 40, 25)),
        PackageVersion(value=("9.5.16",), release_date=dt_local(2020, 4, 28, 9, 22, 14)),
        PackageVersion(value=("9.5.17",), release_date=dt_local(2020, 5, 12, 10, 36)),
        PackageVersion(value=("9.5.18",), release_date=dt_local(2020, 5, 19, 13, 10, 50)),
        PackageVersion(value=("9.5.19",), release_date=dt_local(2020, 6, 9, 8, 44, 34)),
        PackageVersion(value=("9.5.2",), release_date=dt_local(2018, 12, 11, 12, 42, 55)),
        PackageVersion(value=("9.5.3",), release_date=dt_local(2018, 12, 14, 7, 28, 48)),
        PackageVersion(value=("9.5.4",), release_date=dt_local(2019, 1, 22, 10, 12, 4)),
        PackageVersion(value=("9.5.5",), release_date=dt_local(2019, 3, 4, 20, 25, 8)),
        PackageVersion(value=("9.5.6",), release_date=dt_local(2019, 5, 7, 10, 16, 30)),
        PackageVersion(value=("9.5.7",), release_date=dt_local(2019, 5, 15, 11, 41, 51)),
        PackageVersion(value=("9.5.8",), release_date=dt_local(2019, 6, 25, 8, 28, 51)),
        PackageVersion(value=("9.5.9",), release_date=dt_local(2019, 8, 20, 9, 33, 35)),
    ]

    def test_extract_versions(self):
        with open(os.path.join(TEST_DATA, "composer.json")) as f:
            mock_response = json.load(f)

        results = list(ComposerVersionAPI().extract_versions(mock_response, "typo3/cms-core"))
        assert results == self.expected_versions

    @mock.patch("vulnerabilities.package_managers.get_response")
    def test_fetch(self, mock_response):
        with open(os.path.join(TEST_DATA, "composer.json")) as f:
            mock_response.return_value = json.load(f)

        results = list(ComposerVersionAPI().fetch("typo3/cms-core"))
        assert results == self.expected_versions


class TestMavenVersionAPI:
    def test_extract_versions(self):
        import xml.etree.ElementTree as ET

        with open(os.path.join(TEST_DATA, "maven-metadata.xml")) as f:
            mock_response = ET.parse(f)

        results = list(MavenVersionAPI().extract_versions(mock_response))
        expected = [PackageVersion("1.2.2"), PackageVersion("1.2.3"), PackageVersion("1.3.0")]
        assert results == expected

    def test_artifact_url(self):
        eg_comps1 = ["org.apache", "kafka"]
        eg_comps2 = ["apple.msft.windows.mac.oss", "exfat-ntfs"]

        url1 = MavenVersionAPI.artifact_url(eg_comps1)
        url2 = MavenVersionAPI.artifact_url(eg_comps2)

        assert url1 == "https://repo1.maven.org/maven2/org/apache/kafka/maven-metadata.xml"
        assert (
            url2
            == "https://repo1.maven.org/maven2/apple/msft/windows/mac/oss/exfat-ntfs/maven-metadata.xml"
        )

    @mock.patch("vulnerabilities.package_managers.get_response")
    def test_get_until(self, mock_response):
        with open(os.path.join(TEST_DATA, "maven-metadata.xml"), "rb") as f:
            mock_response.return_value = f.read()

        assert MavenVersionAPI().get_until("org.apache:kafka") == VersionResponse(
            valid_versions={"1.3.0", "1.2.2", "1.2.3"}, newer_versions=set()
        )

    @mock.patch("vulnerabilities.package_managers.get_response")
    def test_fetch(self, mock_response):
        with open(os.path.join(TEST_DATA, "maven-metadata.xml"), "rb") as f:
            mock_response.return_value = f.read()

        expected = [
            PackageVersion(value="1.2.2"),
            PackageVersion(value="1.2.3"),
            PackageVersion(value="1.3.0"),
        ]
        results = list(MavenVersionAPI().fetch("org.apache:kafka"))
        assert results == expected


class TestGoproxyVersionAPI:
    def test_trim_go_url_path(self):

        url1 = "https://pkg.go.dev/github.com/containous/traefik/v2"
        assert GoproxyVersionAPI.trim_go_url_path(url1) == "github.com/containous/traefik"

        url2 = "github.com/FerretDB/FerretDB/cmd/ferretdb"
        assert GoproxyVersionAPI.trim_go_url_path(url2) == "github.com/FerretDB/FerretDB"

        url3 = GoproxyVersionAPI.trim_go_url_path(url2)
        assert GoproxyVersionAPI.trim_go_url_path(url3) == "github.com/FerretDB/FerretDB"

    def test_escape_path(self):
        path = "github.com/FerretDB/FerretDB"
        expected = "github.com/!ferret!d!b/!ferret!d!b"
        assert GoproxyVersionAPI.escape_path(path) == expected

    @mock.patch("vulnerabilities.package_managers.get_response")
    def test_fetch_version_info(self, mock_response):
        mock_response.return_value = {"Version": "v0.0.5", "Time": "2022-01-04T13:54:01Z"}
        result = GoproxyVersionAPI.fetch_version_info(
            "v0.0.5",
            "github.com/!ferret!d!b/!ferret!d!b",
        )
        expected = PackageVersion(
            value="v0.0.5",
            release_date=dt_local(2022, 1, 4, 13, 54, 1),
        )
        assert result == expected

    @mock.patch("vulnerabilities.package_managers.get_response")
    def test_fetch(self, mock_fetcher):
        # we have many calls made to get_response
        versions_list = "v0.0.1\nv0.0.5\nv0.0.3\nv0.0.4\nv0.0.2\n"
        responses = [
            versions_list,
            {"Version": "v0.0.1", "Time": "2021-11-02T06:56:38Z"},
            {"Version": "v0.0.2", "Time": "2021-11-13T21:36:37Z"},
            {"Version": "v0.0.3", "Time": "2021-11-19T20:31:22Z"},
            {"Version": "v0.0.4", "Time": "2021-12-01T19:02:44Z"},
            {"Version": "v0.0.5", "Time": "2022-01-04T13:54:01Z"},
        ]
        mock_fetcher.side_effect = responses

        results = list(GoproxyVersionAPI().fetch("github.com/FerretDB/FerretDB"))
        expected = [
            PackageVersion(value="v0.0.1", release_date=dt_local(2021, 11, 2, 6, 56, 38)),
            PackageVersion(value="v0.0.5", release_date=dt_local(2021, 11, 13, 21, 36, 37)),
            PackageVersion(value="v0.0.3", release_date=dt_local(2021, 11, 19, 20, 31, 22)),
            PackageVersion(value="v0.0.4", release_date=dt_local(2021, 12, 1, 19, 2, 44)),
            PackageVersion(value="v0.0.2", release_date=dt_local(2022, 1, 4, 13, 54, 1)),
        ]
        assert results == expected

    @mock.patch("vulnerabilities.package_managers.get_response")
    def test_fetch_with_responses_are_none(self, mock_fetcher):
        # we have many calls made to get_response
        responses = [None, None, None, None, None]
        mock_fetcher.side_effect = responses

        results = list(GoproxyVersionAPI().fetch("github.com/FerretDB/FerretDB"))
        assert results == []


class TestNugetVersionAPI:
    expected_versions = [
        PackageVersion(value="0.23.0", release_date=dt_local(2018, 1, 17, 9, 32, 59, 283000)),
        PackageVersion(value="0.24.0", release_date=dt_local(2018, 3, 30, 7, 25, 18, 393000)),
        PackageVersion(value="1.0.0", release_date=dt_local(2018, 9, 13, 8, 16, 0, 420000)),
        PackageVersion(value="1.0.1", release_date=dt_local(2020, 1, 17, 15, 31, 41, 857000)),
        PackageVersion(value="1.0.2", release_date=dt_local(2020, 4, 21, 12, 24, 53, 877000)),
        PackageVersion(
            value="2.0.0-preview01", release_date=dt_local(2018, 1, 9, 17, 12, 20, 440000)
        ),
        PackageVersion(value="2.0.0", release_date=dt_local(2018, 9, 27, 13, 33, 15, 370000)),
        PackageVersion(value="2.1.0", release_date=dt_local(2018, 10, 16, 6, 59, 44, 680000)),
        PackageVersion(value="2.2.0", release_date=dt_local(2018, 11, 23, 8, 13, 8, 3000)),
        PackageVersion(value="2.3.0", release_date=dt_local(2019, 6, 27, 14, 27, 31, 613000)),
        PackageVersion(value="2.4.0", release_date=dt_local(2020, 1, 17, 15, 11, 5, 810000)),
        PackageVersion(value="2.5.0", release_date=dt_local(2020, 3, 24, 14, 22, 39, 960000)),
        PackageVersion(value="2.6.0", release_date=dt_local(2020, 3, 27, 11, 6, 27, 500000)),
        PackageVersion(value="2.7.0", release_date=dt_local(2020, 4, 21, 12, 27, 36, 427000)),
    ]

    def test_extract_versions(self):
        with open(os.path.join(TEST_DATA, "nuget_index.json")) as f:
            mock_response = json.load(f)
        results = list(NugetVersionAPI().extract_versions(mock_response))
        assert results == self.expected_versions

    @mock.patch("vulnerabilities.package_managers.get_response")
    def test_fetch(self, mock_response):
        with open(os.path.join(TEST_DATA, "nuget_index.json")) as f:
            mock_response.return_value = json.load(f)
        results = list(NugetVersionAPI().fetch("Exfat.Ntfs"))
        assert results == self.expected_versions


class TestGitHubTagsAPI:
    @mock.patch("vulnerabilities.utils.fetch_github_graphql_query")
    def test_fetch_large_repo(self, mock_fetcher):
        reponse_files = [
            "github-torvalds-linux-0.json",
            "github-torvalds-linux-1.json",
            "github-torvalds-linux-2.json",
            "github-torvalds-linux-3.json",
            "github-torvalds-linux-4.json",
            "github-torvalds-linux-5.json",
            "github-torvalds-linux-6.json",
            "github-torvalds-linux-7.json",
        ]
        side_effects = []
        for response_file in reponse_files:
            with open(os.path.join(TEST_DATA, "github", response_file)) as f:
                side_effects.append(json.load(f))
        mock_fetcher.side_effect = side_effects

        results = list(GitHubTagsAPI().fetch("torvalds/linux"))
        assert len(results) == 739

    @mock.patch("vulnerabilities.utils.fetch_github_graphql_query")
    def test_fetch_small_repo_1(self, mock_graphql_response):
        with open(os.path.join(TEST_DATA, "github", "github-nexb-scancode-toolkit-0.json")) as f:
            mock_graphql_response.return_value = json.load(f)
        results = list(GitHubTagsAPI().fetch("nexB/scancode-toolkit"))
        expected = [
            PackageVersion(value="v1.0.0", release_date=dt_local(2015, 7, 1, 15, 14, 15)),
            PackageVersion(value="v1.1.0", release_date=dt_local(2015, 7, 6, 10, 9, 51)),
            PackageVersion(value="v1.2.0", release_date=dt_local(2015, 7, 13, 14, 56, 45)),
            PackageVersion(value="v1.2.1", release_date=dt_local(2015, 7, 13, 16, 36, 42)),
            PackageVersion(value="v1.2.2", release_date=dt_local(2015, 7, 14, 14, 10, 20)),
            PackageVersion(value="v1.2.3", release_date=dt_local(2015, 7, 16, 6, 53, 40)),
            PackageVersion(value="v1.2.4", release_date=dt_local(2015, 7, 22, 14, 6, 14)),
            PackageVersion(value="v1.3.0", release_date=dt_local(2015, 7, 24, 12, 20, 54)),
            PackageVersion(value="v1.3.1", release_date=dt_local(2015, 7, 27, 18, 46, 11)),
            PackageVersion(value="v1.4.0", release_date=dt_local(2015, 11, 24, 18, 15, 21)),
            PackageVersion(value="v1.4.1", release_date=dt_local(2015, 12, 3, 11, 22, 26)),
            PackageVersion(value="v1.4.2", release_date=dt_local(2015, 12, 3, 11, 39, 30)),
            PackageVersion(value="v1.4.3", release_date=dt_local(2015, 12, 10, 17, 7, 19)),
            PackageVersion(value="v1.5.0", release_date=dt_local(2015, 12, 15, 14, 57, 37)),
            PackageVersion(value="v1.6.0", release_date=dt_local(2016, 1, 29, 21, 50, 30)),
            PackageVersion(value="v1.6.1", release_date=dt_local(2016, 3, 1, 19, 49, 6)),
            PackageVersion(value="v1.6.2", release_date=dt_local(2016, 6, 24, 14, 35, 1)),
            PackageVersion(value="v1.6.3", release_date=dt_local(2016, 6, 24, 16, 4, 25)),
            PackageVersion(value="v2.0.0.rc1", release_date=dt_local(2016, 10, 7, 20, 49, 42)),
            PackageVersion(value="v2.0.0.rc2", release_date=dt_local(2017, 1, 16, 14, 34, 49)),
            PackageVersion(value="v2.0.0.rc3", release_date=dt_local(2017, 6, 16, 15, 56, 50)),
            PackageVersion(value="v2.0.0", release_date=dt_local(2017, 6, 23, 8, 7, 3)),
            PackageVersion(value="v2.0.1", release_date=dt_local(2017, 7, 3, 16, 0, 36)),
            PackageVersion(value="v2.1.0", release_date=dt_local(2017, 9, 22, 19, 34, 57)),
            PackageVersion(value="v2.2.0", release_date=dt_local(2017, 10, 5, 22, 41, 56)),
            PackageVersion(value="v2.2.1", release_date=dt_local(2017, 10, 5, 22, 53, 25)),
            PackageVersion(value="v2.9.0b1", release_date=dt_local(2018, 3, 2, 21, 18, 40)),
            PackageVersion(value="v2.9.1", release_date=dt_local(2018, 3, 22, 15, 44, 33)),
            PackageVersion(value="v2.9.2", release_date=dt_local(2018, 5, 8, 13, 54, 52)),
            PackageVersion(value="v2.9.3", release_date=dt_local(2018, 9, 27, 21, 11, 57)),
            PackageVersion(value="v2.9.4", release_date=dt_local(2018, 10, 19, 14, 31, 36)),
            PackageVersion(value="v2.9.5", release_date=dt_local(2018, 10, 22, 20, 33, 50)),
            PackageVersion(value="v2.9.6", release_date=dt_local(2018, 10, 25, 20, 26, 28)),
            PackageVersion(value="v2.9.7", release_date=dt_local(2018, 10, 26, 1, 55, 40)),
            PackageVersion(value="v2.9.8", release_date=dt_local(2018, 12, 12, 10, 13, 24)),
            PackageVersion(value="v2.9.9", release_date=dt_local(2019, 1, 7, 11, 20, 18)),
            PackageVersion(value="v3.0.0", release_date=dt_local(2019, 2, 14, 19, 15, 6)),
            PackageVersion(value="v3.0.1", release_date=dt_local(2019, 2, 15, 14, 17, 54)),
            PackageVersion(value="v3.0.2", release_date=dt_local(2019, 2, 15, 14, 34, 52)),
            PackageVersion(value="v3.1.0", release_date=dt_local(2019, 8, 12, 18, 31, 48)),
            PackageVersion(value="v3.1.1", release_date=dt_local(2019, 9, 3, 20, 27, 57)),
            PackageVersion(value="v3.2.0rc1", release_date=dt_local(2020, 9, 8, 18, 12, 16)),
            PackageVersion(value="v3.2.1rc2", release_date=dt_local(2020, 9, 11, 15, 28, 54)),
            PackageVersion(value="v3.2.2rc3", release_date=dt_local(2020, 10, 14, 22, 18)),
            PackageVersion(value="v3.2.3", release_date=dt_local(2020, 10, 27, 18, 44, 17)),
            PackageVersion(value="v21.2.9", release_date=dt_local(2021, 2, 9, 18, 0, 14)),
            PackageVersion(value="v21.2.25", release_date=dt_local(2021, 2, 25, 21, 6, 9)),
            PackageVersion(value="v21.3.30", release_date=dt_local(2021, 3, 31, 17, 36, 32)),
            PackageVersion(value="v21.3.31", release_date=dt_local(2021, 4, 1, 7, 21, 52)),
            PackageVersion(value="v21.6.7", release_date=dt_local(2021, 6, 8, 8, 27, 29)),
            PackageVersion(value="v21.7.30", release_date=dt_local(2021, 7, 30, 20, 12, 30)),
            PackageVersion(value="v21.8.4", release_date=dt_local(2021, 8, 4, 17, 42, 25)),
            PackageVersion(value="v30.0.0", release_date=dt_local(2021, 9, 23, 10, 41, 40)),
            PackageVersion(value="v30.0.1", release_date=dt_local(2021, 9, 24, 10, 1, 28)),
            PackageVersion(value="v30.1.0", release_date=dt_local(2021, 9, 26, 14, 31, 56)),
        ]
        assert results == expected

    @mock.patch("vulnerabilities.utils.fetch_github_graphql_query")
    def test_fetch_small_repo_2(self, mock_graphql_response):
        with open(os.path.join(TEST_DATA, "github", "github-nexb-vulnerablecode-0.json")) as f:
            mock_graphql_response.return_value = json.load(f)
        results = list(GitHubTagsAPI().fetch("nexB/vulnerablecode"))
        expected = [
            PackageVersion(value="v0.1", release_date=dt_local(2019, 12, 3, 13, 48, 53)),
            PackageVersion(value="v20.10", release_date=dt_local(2020, 9, 28, 12, 31, 16)),
            PackageVersion(value="v22.01", release_date=dt_local(2022, 1, 24, 23, 48, 4)),
        ]
        assert results == expected
