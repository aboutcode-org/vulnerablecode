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
from pathlib import Path

import defusedxml.ElementTree as DET
import pytest
from commoncode import testcase
from django.db.models.query import QuerySet
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import OpensslVersionRange
from univers.versions import OpensslVersion

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importers import openssl
from vulnerabilities.improvers import default
from vulnerabilities.tests import util_tests

ADVISORY_FIELDS_TO_TEST = (
    "unique_content_id",
    "aliases",
    "summary",
    "affected_packages",
    "references",
    "date_published",
)


class TestOpenssl(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "openssl")

    def test_parse_vulnerabilities(self):
        xml_page = self.get_test_loc("security_advisories.xml")
        with open(xml_page) as f:
            xml_response = f.read()
        results = [data.to_dict() for data in openssl.parse_vulnerabilities(xml_response)]
        expected_file = self.get_test_loc(
            "security_advisories-advisory_data-expected.json", must_exist=False
        )
        util_tests.check_results_against_json(results, expected_file)

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
        assert expected == openssl.to_advisory_data(issue_parsed)

    @pytest.mark.django_db(transaction=True)
    def test_OpensslImporter(self):

        expected_file = self.get_test_loc(
            "security_advisories-importer-expected.json", must_exist=False
        )

        results = self.run_import()
        datetime_to_isoformat(results)
        util_tests.check_results_against_json(results, expected_file)

        # run again as there should be no duplicates
        results = self.run_import()
        datetime_to_isoformat(results)
        util_tests.check_results_against_json(results, expected_file)

    def run_import(self):
        """
        Return a list of imported Advisory model objects.
        """

        class MockOpensslImporter(openssl.OpensslImporter):
            """
            A mocked OpensslImporter that loads content from a file rather than
            making a network call.
            """

            def fetch(self):
                with open(test_file) as tf:
                    return tf.read()

        test_file = self.get_test_loc("security_advisories.xml")

        ImportRunner(MockOpensslImporter).run()
        return list(models.Advisory.objects.all().values(*ADVISORY_FIELDS_TO_TEST))

    @pytest.mark.django_db(transaction=True)
    def test_DefaultImprover_inferences_on_Openssl(self):

        with open(self.get_test_loc("improver/improver-advisories.json")) as vf:
            advisories_data = json.load(vf)

        results = []
        improver = default.DefaultImprover()
        for advdata in advisories_data:
            advisory_data = AdvisoryData.from_dict(advdata)

            inferences = improver.get_inferences(advisory_data=advisory_data)
            for i in inferences:
                i.vulnerability_id = "PLAIN-ID-FOR-TESTING"
                results.append(i.to_dict())

        expected_file = self.get_test_loc(
            "improver/improver-inferences-expected.json", must_exist=False
        )
        util_tests.check_results_against_json(results, expected_file)


def datetime_to_isoformat(advisories):
    for advisory in advisories:
        advisory["date_published"] = advisory["date_published"].isoformat()
