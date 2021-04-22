# Copyright (c)  nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
import json
from unittest import TestCase
from unittest.mock import patch
from unittest.mock import MagicMock
from unittest.mock import call
import xml.etree.ElementTree as ET
from collections import OrderedDict

from requests.models import Response
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.importers.github import GitHubAPIDataSource
from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.package_managers import NugetVersionAPI
from vulnerabilities.package_managers import ComposerVersionAPI
from vulnerabilities.severity_systems import ScoringSystem
from vulnerabilities.importers.github import GitHubTokenError
from vulnerabilities.importers.github import query
from vulnerabilities.helpers import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


class TestGitHubAPIDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            "endpoint": "https://api.example.com/graphql",
            "ecosystems": ["MAVEN"],
        }
        with patch.dict(os.environ, {"GH_TOKEN": "abc"}):
            cls.data_src = GitHubAPIDataSource(1, config=data_source_cfg)

    def tearDown(self):
        setattr(self.data_src, "version_api", None)

    def test_categorize_versions(self):
        eg_version_range = ">= 3.3.0, < 3.3.5"
        eg_versions = ["3.3.6", "3.3.0", "3.3.4", "3.2.0"]

        aff_vers, safe_vers = self.data_src.categorize_versions(
            "pypi", eg_version_range, eg_versions
        )
        exp_safe_vers = ["3.3.6", "3.2.0"]
        exp_aff_vers = ["3.3.0", "3.3.4"]

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

        call_1 = call(self.data_src.config.endpoint, headers=exp_headers, json=first_query)
        call_2 = call(self.data_src.config.endpoint, headers=exp_headers, json=second_query)

        assert mock.call_args_list[0] == call_1
        assert mock.call_args_list[1] == call_2

    def test_set_version_api(self):

        with patch("vulnerabilities.importers.github.GitHubAPIDataSource.set_api"):
            with patch("vulnerabilities.importers.github.GitHubAPIDataSource.collect_packages"):
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

        expected_advisories = [
            Advisory(
                summary="Denial of Service in Tomcat",
                references=[
                    Reference(
                        reference_id="GHSA-qcxh-w3j9-58qr",
                        url="https://github.com/advisories/GHSA-qcxh-w3j9-58qr",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3.1_qr",
                                    name="CVSSv3.1 Qualitative Severity Rating",
                                    url="https://www.first.org/cvss/specification-document#Qualitative-Severity-Rating-Scale",
                                    notes="A textual interpretation of severity. Has values like HIGH, MODERATE etc",  # nopep8
                                ),
                                value="MODERATE",
                            )
                        ],
                    )
                ],
                vulnerability_id="CVE-2019-0199",
            ),
            Advisory(
                summary="Denial of Service in Tomcat",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="maven",
                            namespace="org.apache.tomcat.embed",
                            name="tomcat-embed-core",
                            version="9.0.2",
                            qualifiers={},
                            subpath=None,
                        )
                    )
                ],
                references=[
                    Reference(
                        reference_id="GHSA-qcxh-w3j9-58qr",
                        url="https://github.com/advisories/GHSA-qcxh-w3j9-58qr",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3.1_qr",
                                    name="CVSSv3.1 Qualitative Severity Rating",
                                    url="https://www.first.org/cvss/specification-document#Qualitative-Severity-Rating-Scale",
                                    notes="A textual interpretation of severity. Has values like HIGH, MODERATE etc",  # nopep8
                                ),
                                value="HIGH",
                            )
                        ],
                    )
                ],
                vulnerability_id="CVE-2019-0199",
            ),
            Advisory(
                summary="Improper Input Validation in Tomcat",
                references=[
                    Reference(
                        reference_id="GHSA-c9hw-wf7x-jp9j",
                        url="https://github.com/advisories/GHSA-c9hw-wf7x-jp9j",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3.1_qr",
                                    name="CVSSv3.1 Qualitative Severity Rating",
                                    url="https://www.first.org/cvss/specification-document#Qualitative-Severity-Rating-Scale",
                                    notes="A textual interpretation of severity. Has values like HIGH, MODERATE etc",  # nopep8
                                ),
                                value="LOW",
                            )
                        ],
                    )
                ],
                vulnerability_id="CVE-2020-1938",
            ),
            Advisory(
                summary="Improper Input Validation in Tomcat",
                references=[
                    Reference(
                        reference_id="GHSA-c9hw-wf7x-jp9j",
                        url="https://github.com/advisories/GHSA-c9hw-wf7x-jp9j",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3.1_qr",
                                    name="CVSSv3.1 Qualitative Severity Rating",
                                    url="https://www.first.org/cvss/specification-document#Qualitative-Severity-Rating-Scale",
                                    notes="A textual interpretation of severity. Has values like HIGH, MODERATE etc",  # nopep8
                                ),
                                value="MODERATE",
                            )
                        ],
                    )
                ],
                vulnerability_id="CVE-2020-1938",
            ),
            Advisory(
                summary="Improper Input Validation in Tomcat",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="maven",
                            namespace="org.apache.tomcat.embed",
                            name="tomcat-embed-core",
                            version="9.0.2",
                        )
                    )
                ],
                references=[
                    Reference(
                        reference_id="GHSA-c9hw-wf7x-jp9j",
                        url="https://github.com/advisories/GHSA-c9hw-wf7x-jp9j",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3.1_qr",
                                    name="CVSSv3.1 Qualitative Severity Rating",
                                    url="https://www.first.org/cvss/specification-document#Qualitative-Severity-Rating-Scale",
                                    notes="A textual interpretation of severity. Has values like HIGH, MODERATE etc",  # nopep8
                                ),
                                value="LOW",
                            )
                        ],
                    )
                ],
                vulnerability_id="CVE-2020-1938",
            ),
        ]

        mock_version_api = MagicMock()
        mock_version_api.package_type = "maven"
        mock_version_api.get = lambda x: {"1.2.0", "9.0.2"}
        with patch(
            "vulnerabilities.importers.github.MavenVersionAPI", return_value=mock_version_api
        ):  # nopep8
            with patch("vulnerabilities.importers.github.GitHubAPIDataSource.set_api"):
                found_advisories = self.data_src.process_response()

        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
