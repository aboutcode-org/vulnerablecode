#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import csv
import os
from unittest import TestCase
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers import ProjectKBMSRImporter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/kbmsr2019", "test_msr_data.csv")


class TestProjectKBMSRImporter(TestCase):
    def test_to_advisories(self):
        with open(TEST_DATA) as f:
            lines = [l for l in f.readlines()]
            test_data = csv.reader(lines)

        found_advisories = ProjectKBMSRImporter.to_advisories(test_data)
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
