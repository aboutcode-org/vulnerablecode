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
from vulnerabilities.importers.postgresql import to_advisories
from vulnerabilities.tests.utils import advisories_are_equal


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/postgresql", "advisories.html")


class TestPostgreSQLDataSource(TestCase):
    def test_to_advisories(self):

        with open(TEST_DATA) as f:
            raw_data = f.read()

        expected_advisories = [
                Advisory(
                    summary="Windows installer runs executables from uncontrolled directories",
                    impacted_package_urls=[
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="postgresql",
                            version="9.5",
                            qualifiers={"os": "windows"},
                            subpath=None,
                        )
                    ],
                    resolved_package_urls=[
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="postgresql",
                            version="9.5.22",
                            qualifiers={"os": "windows"},
                            subpath=None,
                        )
                    ],
                    vuln_references=[
                        Reference(
                            url="https://www.postgresql.org/about/news/postgresql-123-118-1013-9618-and-9522-released-2038/",  # nopep8
                            reference_id="",
                        )
                    ],
                    vulnerability_id="CVE-2020-10733",
                ),
                Advisory(
                    summary="ALTER ... DEPENDS ON EXTENSION is missing authorization checks.",
                    impacted_package_urls=[
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="postgresql",
                            version="11",
                            qualifiers={},
                            subpath=None,
                        ),
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="postgresql",
                            version="12",
                            qualifiers={},
                            subpath=None,
                        ),
                    ],
                    resolved_package_urls=[
                        PackageURL(
                            type="generic",
                            namespace=None,
                            name="postgresql",
                            version=None,
                            qualifiers={},
                            subpath=None,
                        )
                    ],
                    vuln_references=[
                        Reference(
                            url="https://access.redhat.com/security/cve/CVE-2020-1720",
                            reference_id="",
                        ),
                        Reference(
                            url="https://www.postgresql.org/about/news/postgresql-122-117-1012-9617-9521-and-9426-released-2011/",  # nopep8
                            reference_id="",
                        ),
                    ],
                    vulnerability_id="CVE-2020-1720",
                ),
            ]

        found_advisories = to_advisories(raw_data)

        assert advisories_are_equal(expected_advisories, found_advisories)
