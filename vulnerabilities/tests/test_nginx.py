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

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.importers.nginx import NginxDataSource
from vulnerabilities.package_managers import GitHubTagsAPI

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/nginx", "security_advisories.html")


class TestNginxDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        with open(TEST_DATA) as f:
            cls.data = f.read()
        data_source_cfg = {"etags": {}}
        cls.data_src = NginxDataSource(1, config=data_source_cfg)
        cls.data_src.version_api = GitHubTagsAPI(
            cache={"nginx/nginx": {"1.2.3", "1.7.0", "1.3.9", "0.7.52"}}
        )

    def test_to_advisories(self):
        expected_data = sorted(
            [
                Advisory(
                    summary="Stack-based buffer overflow with specially crafted request",
                    impacted_package_urls={
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.3.9",
                            qualifiers={},
                            subpath=None,
                        )
                    },
                    resolved_package_urls={
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.7.0",
                            qualifiers={},
                            subpath=None,
                        )
                    },
                    vuln_references=[],
                    cve_id="CVE-2013-2028",
                ),
                Advisory(
                    summary="Vulnerabilities with Windows directory aliases",
                    impacted_package_urls={
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="0.7.52",
                            qualifiers={"os": "windows"},
                            subpath=None,
                        ),
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.2.3",
                            qualifiers={"os": "windows"},
                            subpath=None,
                        ),
                    },
                    resolved_package_urls={
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.2.3",
                            qualifiers={},
                            subpath=None,
                        ),
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.3.9",
                            qualifiers={},
                            subpath=None,
                        ),
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="1.7.0",
                            qualifiers={},
                            subpath=None,
                        ),
                    },
                    vuln_references=[],
                    cve_id="CVE-2011-4963",
                ),
                Advisory(
                    summary="Vulnerabilities with invalid UTF-8 sequence on Windows",
                    impacted_package_urls={
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="0.7.52",
                            qualifiers={"os": "windows"},
                            subpath=None,
                        )
                    },
                    resolved_package_urls=set(),
                    vuln_references=[],
                    cve_id="CVE-2010-2266",
                ),
                Advisory(
                    summary="An error log data are not sanitized",
                    impacted_package_urls=set(),
                    resolved_package_urls={},
                    vuln_references=[],
                    cve_id="CVE-2009-4487",
                ),
                Advisory(
                    summary="The renegotiation vulnerability in SSL protocol",
                    impacted_package_urls={
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="0.7.52",
                            qualifiers={},
                            subpath=None,
                        )
                    },
                    resolved_package_urls=set(),
                    vuln_references=[],
                    cve_id="CVE-2009-3555",
                ),
                Advisory(
                    summary="Directory traversal vulnerability",
                    impacted_package_urls={
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="nginx",
                            version="0.7.52",
                            qualifiers={},
                            subpath=None,
                        )
                    },
                    resolved_package_urls=set(),
                    vuln_references=[],
                    cve_id="CVE-2009-3898",
                ),
            ],
            key=lambda adv: adv.cve_id,
        )

        found_data = sorted(self.data_src.to_advisories(self.data), key=lambda adv: adv.cve_id)

        assert expected_data == found_data
