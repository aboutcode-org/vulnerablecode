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

from packageurl import PackageURL

from vulnerabilities.helpers import AffectedPackage
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.postgresql import to_advisories
from vulnerabilities.severity_systems import ScoringSystem

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/postgresql", "advisories.html")


class TestPostgreSQLImporter(TestCase):
    def test_to_advisories(self):

        with open(TEST_DATA) as f:
            raw_data = f.read()

        expected_advisories = [
            Advisory(
                summary="ALTER ... DEPENDS ON EXTENSION is missing authorization checks.more details",
                vulnerability_id="CVE-2020-1720",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="10",
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="10.12",
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="11",
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="11.7",
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="12",
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="12.2",
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="9.6",
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="9.6.17",
                        ),
                    ),
                ],
                references=[
                    Reference(
                        reference_id="",
                        url="https://www.postgresql.org/about/news/postgresql-122-117-1012-9617-9521-and-9426-released-2011/",
                    ),
                    Reference(
                        reference_id="",
                        url="https://www.postgresql.org/support/security/CVE-2020-1720/",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3",
                                    name="CVSSv3 Base Score",
                                    url="https://www.first.org/cvss/v3-0/",
                                    notes="cvssv3 base score",
                                ),
                                value="3.1",
                            ),
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3_vector",
                                    name="CVSSv3 Vector",
                                    url="https://www.first.org/cvss/v3-0/",
                                    notes="cvssv3 vector, used to get additional info about nature and severity of vulnerability",
                                ),
                                value=["AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N"],
                            ),
                        ],
                    ),
                ],
            ),
            Advisory(
                summary="Windows installer runs executables from uncontrolled directoriesmore details",
                vulnerability_id="CVE-2020-10733",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="10",
                            qualifiers={"os": "windows"},
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="10.13",
                            qualifiers={"os": "windows"},
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="11",
                            qualifiers={"os": "windows"},
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="11.8",
                            qualifiers={"os": "windows"},
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="12",
                            qualifiers={"os": "windows"},
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="12.3",
                            qualifiers={"os": "windows"},
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="9.6",
                            qualifiers={"os": "windows"},
                        ),
                        patched_package=PackageURL(
                            type="generic",
                            name="postgresql",
                            version="9.6.18",
                            qualifiers={"os": "windows"},
                        ),
                    ),
                ],
                references=[
                    Reference(
                        reference_id="",
                        url="https://www.postgresql.org/about/news/postgresql-123-118-1013-9618-and-9522-released-2038/",
                    ),
                    Reference(
                        reference_id="",
                        url="https://www.postgresql.org/support/security/CVE-2020-10733/",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3",
                                    name="CVSSv3 Base Score",
                                    url="https://www.first.org/cvss/v3-0/",
                                    notes="cvssv3 base score",
                                ),
                                value="6.7",
                            ),
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3_vector",
                                    name="CVSSv3 Vector",
                                    url="https://www.first.org/cvss/v3-0/",
                                    notes="cvssv3 vector, used to get additional info about nature and severity of vulnerability",
                                ),
                                value=["AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"],
                            ),
                        ],
                    ),
                ],
            ),
        ]

        found_advisories = to_advisories(raw_data)

        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
