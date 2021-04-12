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
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
from unittest.mock import MagicMock
from unittest.mock import patch
from unittest import TestCase

from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.importers.apache_tomcat import ApacheTomcatDataSource

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "apache_tomcat", "security-9.html")


class TestApacheTomcatDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {"etags": {}}
        mock_api = {"org.apache.tomcat:tomcat": ["9.0.0.M1", "9.0.0.M2", "8.0.0.M1", "6.0.0M2"]}
        with patch("vulnerabilities.importers.apache_tomcat.MavenVersionAPI"):
            with patch("vulnerabilities.importers.apache_tomcat.asyncio"):
                cls.data_src = ApacheTomcatDataSource(1, config=data_source_cfg)

        cls.data_src.version_api = mock_api

    def test_to_advisories(self):
        expected_advisories = [
            Advisory(
                summary="",
                vulnerability_id="CVE-2015-5351",
                impacted_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="8.0.0.M1",
                        qualifiers={},
                        subpath=None,
                    ),
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M1",
                        qualifiers={},
                        subpath=None,
                    ),
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M2",
                        qualifiers={},
                        subpath=None,
                    ),
                },
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M3",
                        qualifiers={},
                        subpath=None,
                    )
                },
                references=[
                    Reference(
                        reference_id="",
                        url="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5351",
                        severities=[],
                    ),
                    Reference(
                        reference_id="",
                        url="https://svn.apache.org/viewvc?view=rev&rev=1720652",
                        severities=[],
                    ),
                    Reference(
                        reference_id="",
                        url="https://svn.apache.org/viewvc?view=rev&rev=1720655",
                        severities=[],
                    ),
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="CVE-2016-0706",
                impacted_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M1",
                        qualifiers={},
                        subpath=None,
                    )
                },
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M3",
                        qualifiers={},
                        subpath=None,
                    )
                },
                references=[
                    Reference(
                        reference_id="",
                        url="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0706",
                        severities=[],
                    ),
                    Reference(
                        reference_id="",
                        url="https://svn.apache.org/viewvc?view=rev&rev=1722799",
                        severities=[],
                    ),
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="CVE-2016-0714",
                impacted_package_urls=set(),
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M3",
                        qualifiers={},
                        subpath=None,
                    )
                },
                references=[
                    Reference(
                        reference_id="",
                        url="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0714",
                        severities=[],
                    ),
                    Reference(
                        reference_id="",
                        url="https://svn.apache.org/viewvc?view=rev&rev=1725263",
                        severities=[],
                    ),
                    Reference(
                        reference_id="",
                        url="https://svn.apache.org/viewvc?view=rev&rev=1725914",
                        severities=[],
                    ),
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="CVE-2016-0763",
                impacted_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M1",
                        qualifiers={},
                        subpath=None,
                    ),
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M2",
                        qualifiers={},
                        subpath=None,
                    ),
                },
                resolved_package_urls={
                    PackageURL(
                        type="maven",
                        namespace="apache",
                        name="tomcat",
                        version="9.0.0.M3",
                        qualifiers={},
                        subpath=None,
                    )
                },
                references=[
                    Reference(
                        reference_id="",
                        url="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0763",
                        severities=[],
                    ),
                    Reference(
                        reference_id="",
                        url="https://svn.apache.org/viewvc?view=rev&rev=1725926",
                        severities=[],
                    ),
                ],
            ),
        ]

        with open(TEST_DATA) as f:
            found_advisories = self.data_src.to_advisories(f)

        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
