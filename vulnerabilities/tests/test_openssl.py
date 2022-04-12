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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.


import datetime
import json
import os
import unittest

import defusedxml.ElementTree as DET
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import OpensslVersionRange
from univers.versions import OpensslVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importers.openssl import parse_vulnerabilities
from vulnerabilities.importers.openssl import to_advisory_data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "openssl")


class TestOpenssl(unittest.TestCase):
    # use regen flag to generates the expected_file
    def test_parse_vulnerabilities(self, regen=False):
        xml_page = os.path.join(TEST_DATA, "openssl_xml_data.xml")
        with open(xml_page) as f:
            xml_response = f.read()
        result = [data.to_dict() for data in parse_vulnerabilities(xml_response)]

        expected_file = os.path.join(TEST_DATA, "openssl-expected.json")
        if regen:
            with open(expected_file, "w") as f:
                json.dump(result, f, indent=2)
            expected = result
        else:
            with open(expected_file) as f:
                expected = json.load(f)
        assert result == expected

    def test_to_advisory_data(self):
        issue_string = """<issue public="20171207">
            <cve name="2017-3737"/>
            <affects base="1.0.2" version="1.0.2b"/>
            <affects base="1.0.2" version="1.0.2c"/>
            <fixed base="1.0.2" version="1.0.2n" date="20171207">
                <git hash="898fb884b706aaeb283de4812340bb0bde8476dc"/>
            </fixed>
            <problemtype>Unauthenticated read/unencrypted write</problemtype>
            <title>Read/write after SSL object in error state</title>
            <description> OpenSSL 1.0.2 (starting from version 1.0.2b) introduced an "error state"</description>
            <advisory url="/news/secadv/20171207.txt"/>
            <reported source="David Benjamin (Google)"/>
        </issue>"""

        expected = AdvisoryData(
            aliases=["CVE-2017-3737", "VC-OPENSSL-20171207-CVE-2017-3737"],
            summary='OpenSSL 1.0.2 (starting from version 1.0.2b) introduced an "error state"',
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(
                        type="openssl",
                        namespace=None,
                        name="openssl",
                        version=None,
                        qualifiers={},
                        subpath=None,
                    ),
                    affected_version_range=OpensslVersionRange(
                        constraints=(
                            VersionConstraint(
                                comparator="=", version=OpensslVersion(string="1.0.2b")
                            ),
                            VersionConstraint(
                                comparator="=", version=OpensslVersion(string="1.0.2c")
                            ),
                        )
                    ),
                    fixed_version=OpensslVersion(string="1.0.2n"),
                )
            ],
            references=[
                Reference(
                    reference_id="CVE-2017-3737",
                    url="",
                    severities=[],
                ),
                Reference(
                    reference_id="",
                    url="https://github.com/openssl/openssl/commit/898fb884b706aaeb283de4812340bb0bde8476dc",
                    severities=[],
                ),
                Reference(
                    reference_id="",
                    url="https://www.openssl.org/news/secadv/20171207.txt",
                    severities=[],
                ),
            ],
            date_published=datetime.datetime(2017, 12, 7, 0, 0, tzinfo=datetime.timezone.utc),
        )
        issue_parsed = DET.fromstring(issue_string)
        assert expected == to_advisory_data(issue_parsed)
