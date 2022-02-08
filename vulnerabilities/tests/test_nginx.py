# Copyright (c) nexB Inc. and others. All rights reserved.
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
from unittest import TestCase
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.importer import Advisory
from vulnerabilities.importers.nginx import NginxImporter
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import Version
from vulnerabilities.helpers import AffectedPackage


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/nginx", "security_advisories.html")


class TestNginxImporter(TestCase):
    @classmethod
    def setUpClass(cls):
        with open(TEST_DATA) as f:
            cls.data = f.read()
        data_source_cfg = {"etags": {}}
        cls.data_src = NginxImporter(1, config=data_source_cfg)
        cls.data_src.version_api = GitHubTagsAPI(
            cache={
                "nginx/nginx": {
                    Version("1.2.3"),
                    Version("1.7.0"),
                    Version("1.3.9"),
                    Version("0.7.52"),
                }
            }
        )

    def test_to_advisories(self):
        expected_advisories = [
            Advisory(
                summary="An error log data are not sanitized",
                vulnerability_id="CVE-2009-4487",
                affected_packages=[],
                references=[],
            ),
            Advisory(
                summary="Directory traversal vulnerability",
                vulnerability_id="CVE-2009-3898",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="0.7.52",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=None,
                    )
                ],
                references=[],
            ),
            Advisory(
                summary="Stack-based buffer overflow with specially crafted request",
                vulnerability_id="CVE-2013-2028",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.3.9",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.7.0",
                            qualifiers={},
                            subpath=None,
                        ),
                    )
                ],
                references=[],
            ),
            Advisory(
                summary="The renegotiation vulnerability in SSL protocol",
                vulnerability_id="CVE-2009-3555",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="0.7.52",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=None,
                    )
                ],
                references=[],
            ),
            Advisory(
                summary="Vulnerabilities with Windows directory aliases",
                vulnerability_id="CVE-2011-4963",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="0.7.52",
                            qualifiers={"os": "windows"},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.2.3",
                            qualifiers={},
                            subpath=None,
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.2.3",
                            qualifiers={"os": "windows"},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.3.9",
                            qualifiers={},
                            subpath=None,
                        ),
                    ),
                ],
                references=[],
            ),
            Advisory(
                summary="Vulnerabilities with invalid UTF-8 sequence on Windows",
                vulnerability_id="CVE-2010-2266",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="0.7.52",
                            qualifiers={"os": "windows"},
                            subpath=None,
                        ),
                        patched_package=None,
                    )
                ],
                references=[],
            ),
        ]
        found_data = self.data_src.to_advisories(self.data)
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        found_data = list(map(Advisory.normalized, found_data))
        assert sorted(found_data) == sorted(expected_advisories)
