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
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
import json
from dateutil import parser as dateparser
from packageurl import PackageURL

from unittest import TestCase

from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems
from vulnerabilities.importers.apache_httpd import ApacheHTTPDDataSource
from vulnerabilities.importers.apache_httpd import fetch_links

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/apache_httpd/CVE-1999-1199.json")


class TestApacheHTTPDDataSource(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {"etags": {}}
        cls.data_src = ApacheHTTPDDataSource(1, config=data_source_cfg)
        with open(TEST_DATA) as f:
            cls.nvd_data = json.load(f)

    def test_to_advisory(self):
        expected_advisories = [
            Advisory(
                summary="A serious problem exists when a client sends a large number of "
                "headers with the same header name. Apache uses up memory faster than the "
                "amount of memory required to simply store the received data itself. That "
                "is, memory use increases faster and faster as more headers are received, "
                "rather than increasing at a constant rate. This makes a denial of service "
                "attack based on this method more effective than methods which cause Apache"
                " to use memory at a constant rate, since the attacker has to send less data.",
                impacted_package_urls=[
                    PackageURL(
                        type="apache",
                        namespace=None,
                        name="httpd",
                        version="1.3.1",
                        qualifiers={},
                        subpath=None,
                    ),
                    PackageURL(
                        type="apache",
                        namespace=None,
                        name="httpd",
                        version="1.3.0",
                        qualifiers={},
                        subpath=None,
                    ),
                ],
                resolved_package_urls=[],
                references=[
                    Reference(
                        url="https://httpd.apache.org/security/json/CVE-1999-1199.json",
                        severities=[
                            VulnerabilitySeverity(
                                system=scoring_systems["apache_httpd"],
                                value="important",
                            ),
                        ],
                        reference_id="CVE-1999-1199",
                    ),
                ],
                vulnerability_id="CVE-1999-1199",
            )
        ]
        found_advisories = [self.data_src.to_advisory(self.nvd_data)]
        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
