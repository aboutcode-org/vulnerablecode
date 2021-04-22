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

import csv
import os
from unittest import TestCase
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.importers import ProjectKBMSRDataSource


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/kbmsr2019", "test_msr_data.csv")


class TestProjectKBMSRDataSource(TestCase):
    def test_to_advisories(self):
        with open(TEST_DATA) as f:
            lines = [l for l in f.readlines()]
            test_data = csv.reader(lines)

        found_advisories = ProjectKBMSRDataSource.to_advisories(test_data)
        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = [
            Advisory(
                summary="",
                vulnerability_id="CVE-2018-11040",
                references=[
                    Reference(
                        reference_id="",
                        url="https://github.com/spring-projects/spring-framework/commit/874859493bbda59739c38c7e52eb3625f247b93",
                        severities=[],
                    )
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="CVE-2013-6408",
                references=[
                    Reference(
                        reference_id="",
                        url="https://github.com/apache/lucene-solr/commit/7239a57a51ea0f4d05dd330ce5e15e4f72f72747",
                        severities=[],
                    )
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="CVE-2015-6748",
                references=[
                    Reference(
                        reference_id="",
                        url="https://github.com/jhy/jsoup/commit/4edb78991f8d0bf87dafde5e01ccd8922065c9b2",
                        severities=[],
                    )
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="CVE-2018-14658",
                references=[
                    Reference(
                        reference_id="",
                        url="https://github.com/keycloak/keycloak/commit/a957e118e6efb35fe7ef3a62acd66341a6523cb7",
                        severities=[],
                    )
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="CVE-2017-1000355",
                references=[
                    Reference(
                        reference_id="",
                        url="https://github.com/jenkinsci/jenkins/commit/701ea95a52afe53bee28f76a3f96eb0e578852e9",
                        severities=[],
                    )
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="CVE-2018-1000844",
                references=[
                    Reference(
                        reference_id="",
                        url="https://github.com/square/retrofit/commit/97057aaae42e54bfbee8acfa8af7dcf37e812342",
                        severities=[],
                    )
                ],
            ),
            Advisory(
                summary="",
                vulnerability_id="",
                references=[
                    Reference(
                        reference_id="HTTPCLIENT-1803",
                        url="https://github.com/apache/httpcomponents-client/commit/0554271750599756d4946c0d7ba43d04b1a7b22",
                        severities=[],
                    )
                ],
            ),
        ]

        assert expected_advisories == found_advisories
