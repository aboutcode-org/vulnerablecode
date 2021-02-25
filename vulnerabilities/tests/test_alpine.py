#
# Copyright (c)  nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
import yaml
from unittest import TestCase
from unittest.mock import patch, MagicMock

from packageurl import PackageURL

from vulnerabilities.data_source import Advisory, Reference
from vulnerabilities.importers.alpine_linux import AlpineDataSource
from vulnerabilities.tests.utils import advisories_are_equal


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "alpine", "v3.11")


class AlpineImportTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_source = AlpineDataSource(batch_size=1)

    def test__process_link(self):
        expected_advisories = [
            Advisory(
                summary="",
                impacted_package_urls=[],
                resolved_package_urls={
                    PackageURL(
                        type="alpine",
                        namespace=None,
                        name="ansible",
                        version="2.9.3-r0",
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    )
                },
                vuln_references=[],
                vulnerability_id="CVE-2019-14904",
            ),
            Advisory(
                summary="",
                impacted_package_urls=[],
                resolved_package_urls={
                    PackageURL(
                        type="alpine",
                        namespace=None,
                        name="ansible",
                        version="2.9.3-r0",
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    )
                },
                vuln_references=[],
                vulnerability_id="CVE-2019-14905",
            ),
            Advisory(
                summary="",
                impacted_package_urls=[],
                resolved_package_urls={
                    PackageURL(
                        type="alpine",
                        namespace=None,
                        name="ansible",
                        version="2.8.6-r0",
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    )
                },
                vuln_references=[],
                vulnerability_id="CVE-2019-14846",
            ),
            Advisory(
                summary="",
                impacted_package_urls=[],
                resolved_package_urls={
                    PackageURL(
                        type="alpine",
                        namespace=None,
                        name="ansible",
                        version="2.8.6-r0",
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    )
                },
                vuln_references=[],
                vulnerability_id="CVE-2019-14856",
            ),
            Advisory(
                summary="",
                impacted_package_urls=[],
                resolved_package_urls={
                    PackageURL(
                        type="alpine",
                        namespace=None,
                        name="ansible",
                        version="2.8.6-r0",
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    )
                },
                vuln_references=[],
                vulnerability_id="CVE-2019-14858",
            ),
            Advisory(
                summary="",
                impacted_package_urls=[],
                resolved_package_urls={
                    PackageURL(
                        type="alpine",
                        namespace=None,
                        name="xen",
                        version="4.12.1-r0",
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    )
                },
                vuln_references=[
                    Reference(
                        url="https://xenbits.xen.org/xsa/advisory-295.html", reference_id="XSA-295"
                    )
                ],
                vulnerability_id="",
            ),
        ]
        mock_requests = MagicMock()
        mock_content = MagicMock()
        with open(os.path.join(TEST_DATA, "main.yaml")) as f:
            mock_requests.get = lambda x: mock_content
            mock_content.content = f
            with patch("vulnerabilities.importers.alpine_linux.requests", new=mock_requests):
                found_advisories = self.data_source._process_link("does not matter")
                assert advisories_are_equal(expected_advisories, found_advisories)
