# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
import json
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock
from unittest.mock import call
import xml.etree.ElementTree as ET
from collections import OrderedDict

from requests.models import Response
from packageurl import PackageURL

from vulnerabilities.importers.github import GitHubAPIDataSource
from vulnerabilities.importers.github import MavenVersionAPI
from vulnerabilities.importers.github import ComposerVersionAPI
from vulnerabilities.importers.github import NugetVersionAPI
from vulnerabilities.importers.github import GitHubTokenError
from vulnerabilities.importers.github import query
from vulnerabilities.data_source import Advisory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


class TestGitHubAPIDataSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "endpoint": "https://api.example.com/graphql",
            "ecosystems": ["MAVEN"],
        }
        # os.environ = {'GH_TOKEN':'abc'}
        with patch.dict(os.environ, {"GH_TOKEN": "abc"}):
            cls.data_src = GitHubAPIDataSource(1, config=data_source_cfg)

    def tearDown(self):
        setattr(self.data_src, "version_api", None)

    def test_categorize_versions(self):
        eg_version_range = ">= 3.3.0, < 3.3.5"
        eg_versions = {"3.3.6", "3.3.0", "3.3.4", "3.2.0"}

        aff_vers, safe_vers = self.data_src.categorize_versions(
            eg_version_range, eg_versions
        )
        exp_safe_vers = {"3.3.6", "3.2.0"}
        exp_aff_vers = {"3.3.0", "3.3.4"}

        assert aff_vers == exp_aff_vers
        assert safe_vers == exp_safe_vers

    def test_fetch_withinvalidtoken(self):
        class MockErrorResponse(MagicMock):
            @staticmethod
            def json():
                return {"message": "Bad credentials"}

        # This test checks whether `fetch` raises an error when there is an Authentication
        # failure.
        exp_headers = {"Authorization": "token abc"}
        first_query = {"query": query % ("MAVEN", "")}
        mock = MockErrorResponse()
        with patch("vulnerabilities.importers.github.requests.post", new=mock):
            self.assertRaises(GitHubTokenError, self.data_src.fetch)
            mock.assert_called_with(
                self.data_src.config.endpoint, headers=exp_headers, json=first_query
            )

    def test_fetch_withvalidtoken(self):
        class MockCorrectResponse(MagicMock):
            has_next_page = False
            # This owes an explanation. The intent of having
            # has_next_page is to obtain different MockCorrectResponse objects
            # the first one should have `has_next_page = True` and other should
            # have  `has_next_page = False`. This is required to test whether
            # GitHubAPIDataSource.fetch stops as expected.

            def json(self):
                self.has_next_page = not self.has_next_page
                return {
                    "data": {
                        "securityVulnerabilities": {
                            "pageInfo": {
                                "endCursor": "page=2",
                                "hasNextPage": self.has_next_page,
                            }
                        }
                    }
                }

        exp_headers = {"Authorization": "token abc"}
        first_query = {"query": query % ("MAVEN", "")}
        second_query = {"query": query % ("MAVEN", 'after: "page=2"')}
        mock = MockCorrectResponse()
        with patch("vulnerabilities.importers.github.requests.post", new=mock):
            resp = self.data_src.fetch()

        call_1 = call(
            self.data_src.config.endpoint, headers=exp_headers, json=first_query
        )
        call_2 = call(
            self.data_src.config.endpoint, headers=exp_headers, json=second_query
        )

        assert mock.call_args_list[0] == call_1
        assert mock.call_args_list[1] == call_2

    def test_set_version_api(self):

        assert getattr(self.data_src, "version_api", None) is None

        self.data_src.set_version_api("MAVEN")
        assert isinstance(self.data_src.version_api, MavenVersionAPI)

        self.data_src.set_version_api("NUGET")
        assert isinstance(self.data_src.version_api, NugetVersionAPI)

        self.data_src.set_version_api("COMPOSER")
        assert isinstance(self.data_src.version_api, ComposerVersionAPI)

    def test_process_name(self):

        expected_1 = ("org.apache", "kafka")
        result_1 = self.data_src.process_name("MAVEN", "org.apache:kafka")
        assert result_1 == expected_1

        expected_2 = (None, "WindowS.nUget.ExIsts")
        result_2 = self.data_src.process_name("NUGET", "WindowS.nUget.ExIsts")
        assert result_2 == expected_2

        expected_3 = ("psf", "black")
        result_3 = self.data_src.process_name("COMPOSER", "psf/black")
        assert result_3 == expected_3

        expected_4 = None
        result_4 = self.data_src.process_name("SAMPLE", "sample?example=True")
        assert result_4 == expected_4

    def test_process_response(self):

        with open(os.path.join(TEST_DATA, "github_api", "response.json")) as f:
            resp = json.load(f)
            self.data_src.advisories = resp

        expected_result = [
            Advisory(
                summary="Denial of Service in Tomcat",
                impacted_package_urls=set(),
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="1.2.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="9.0.2",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                },
                reference_urls=[],
                reference_ids={"GHSA-qcxh-w3j9-58qr"},
                cve_id="CVE-2019-0199",
            ),
            Advisory(
                summary="Denial of Service in Tomcat",
                impacted_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="9.0.2",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    )
                },
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="1.2.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    )
                },
                reference_urls=[],
                reference_ids={"GHSA-qcxh-w3j9-58qr"},
                cve_id="CVE-2019-0199",
            ),
            Advisory(
                summary="Improper Input Validation in Tomcat",
                impacted_package_urls=set(),
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="1.2.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="9.0.2",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                },
                reference_urls=[],
                reference_ids={"GHSA-c9hw-wf7x-jp9j"},
                cve_id="CVE-2020-1938",
            ),
            Advisory(
                summary="Improper Input Validation in Tomcat",
                impacted_package_urls=set(),
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="1.2.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="9.0.2",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    ),
                },
                reference_urls=[],
                reference_ids={"GHSA-c9hw-wf7x-jp9j"},
                cve_id="CVE-2020-1938",
            ),
            Advisory(
                summary="Improper Input Validation in Tomcat",
                impacted_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="9.0.2",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    )
                },
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat.embed",
                        name="tomcat-embed-core",
                        version="1.2.0",
                        qualifiers=OrderedDict(),
                        subpath=None,
                    )
                },
                reference_urls=[],
                reference_ids={"GHSA-c9hw-wf7x-jp9j"},
                cve_id="CVE-2020-1938",
            ),
        ]

        mock_version_api = MagicMock()
        mock_version_api.get = lambda x: {"1.2.0", "9.0.2"}
        with patch(
            "vulnerabilities.importers.github.MavenVersionAPI",
            return_value=mock_version_api,
        ):
            found_result = self.data_src.process_response()

        assert expected_result == found_result


class TestComposerVersionAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = ComposerVersionAPI()
        with open(os.path.join(TEST_DATA, "composer_api", "cms-core.json")) as f:
            cls.response = json.load(f)

        cls.expected_versions = {
            "9.5.3",
            "8.7.30",
            "9.3.1",
            "9.5.1",
            "9.5.11",
            "9.5.6",
            "8.7.18",
            "8.7.15",
            "9.4.0",
            "9.5.7",
            "8.7.21",
            "9.5.12",
            "9.5.14",
            "8.7.27",
            "8.7.17",
            "8.7.9",
            "10.4.3",
            "10.0.0",
            "10.1.0",
            "9.5.13",
            "9.5.5",
            "8.7.22",
            "8.7.10",
            "8.7.24",
            "8.7.13",
            "8.7.14",
            "8.7.19",
            "9.5.17",
            "9.3.2",
            "9.5.15",
            "8.7.8",
            "9.3.3",
            "8.7.32",
            "10.4.0",
            "10.4.1",
            "9.5.18",
            "9.1.0",
            "9.5.19",
            "9.5.2",
            "8.7.26",
            "8.7.20",
            "10.2.0",
            "8.7.31",
            "8.7.11",
            "9.2.1",
            "8.7.25",
            "9.5.10",
            "10.2.2",
            "10.4.2",
            "9.5.9",
            "9.2.0",
            "9.3.0",
            "9.5.16",
            "10.3.0",
            "8.7.7",
            "10.4.4",
            "8.7.12",
            "8.7.29",
            "10.2.1",
            "9.5.8",
            "9.5.4",
            "9.5.0",
            "8.7.28",
            "8.7.23",
            "9.0.0",
            "8.7.16",
        }

    def test_composer_url(self):
        expected_url = "https://repo.packagist.org/p/typo3/cms-core.json"
        found_url = self.version_api.composer_url("typo3/cms-core")
        assert expected_url == found_url

    def test_extract_versions(self):

        found_versions = self.version_api.extract_versions(
            self.response, "typo3/cms-core"
        )
        assert found_versions == self.expected_versions

    def test_load_to_api(self):

        assert self.version_api.get("typo3/cms-core") == set()

        mock_response = MagicMock()
        mock_response.json = lambda: self.response

        with patch(
            "vulnerabilities.importers.github.requests.get", return_value=mock_response
        ):
            self.version_api.load_to_api("typo3/cms-core")

        assert self.version_api.get("typo3/cms-core") == self.expected_versions


class TestMavenVersionAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = MavenVersionAPI()
        with open(os.path.join(TEST_DATA, "maven_api", "maven-metadata.xml")) as f:
            cls.response = ET.parse(f)

    def test_artifact_url(self):
        eg_comps1 = ["org.apache", "kafka"]
        eg_comps2 = ["apple.msft.windows.mac.oss", "exfat-ntfs"]

        url1 = self.version_api.artifact_url(eg_comps1)
        url2 = self.version_api.artifact_url(eg_comps2)

        assert (
            "https://repo.maven.apache.org/maven2/org/apache/kafka/maven-metadata.xml"
            == url1
        )
        assert (
            "https://repo.maven.apache.org/maven2"
            "/apple/msft/windows/mac/oss/exfat-ntfs/maven-metadata.xml" == url2
        )

    def test_extract_versions(self):
        expected_versions = {"1.2.2", "1.2.3", "1.3.0"}
        assert expected_versions == self.version_api.extract_versions(self.response)

    def test_load_to_api(self):

        assert self.version_api.get("org.apache:kafka") == set()

        mock_response = MagicMock()
        mock_response.content = ET.tostring(self.response.getroot())
        expected = {"1.2.3", "1.3.0", "1.2.2"}

        with patch(
            "vulnerabilities.importers.github.requests.get", return_value=mock_response
        ):
            self.version_api.load_to_api("org.apache:kafka")

        assert self.version_api.get("org.apache:kafka") == expected


class TestNugetVersionAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version_api = NugetVersionAPI()
        with open(os.path.join(TEST_DATA, "nuget_api", "index.json")) as f:
            cls.response = json.load(f)

        cls.expected_versions = {
            "0.23.0",
            "0.24.0",
            "1.0.0",
            "1.0.1",
            "1.0.2",
            "2.0.0",
            "2.0.0-preview01",
            "2.6.0",
            "2.1.0",
            "2.2.0",
            "2.3.0",
            "2.4.0",
            "2.5.0",
            "2.7.0",
        }

    def test_nuget_url(self):
        expected_url = (
            "https://api.nuget.org/v3/registration5-semver1/exfat.ntfs/index.json"
        )
        found_url = self.version_api.nuget_url("exfat.ntfs")
        assert expected_url == found_url

    def test_extract_versions(self):

        found_versions = self.version_api.extract_versions(self.response)
        assert self.expected_versions == found_versions

    def test_load_to_api(self):

        assert self.version_api.get("exfat.ntfs") == set()

        mock_response = MagicMock()
        mock_response.json = lambda: self.response

        with patch(
            "vulnerabilities.importers.github.requests.get", return_value=mock_response
        ):
            self.version_api.load_to_api("Exfat.Ntfs")

        assert self.version_api.get("exfat.ntfs") == self.expected_versions
