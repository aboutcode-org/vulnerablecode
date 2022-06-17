#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from unittest import TestCase

from packageurl import PackageURL

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.postgresql import to_advisories
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/postgresql", "advisories.html")


class TestPostgreSQLImporter(TestCase):
    def test_to_advisories(self):

        with open(TEST_DATA) as f:
            raw_data = f.read()

        expected_advisories = [
            AdvisoryData(
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
                                system=severity_systems.CVSSV3,
                                value="3.1",
                            ),
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV3_VECTOR,
                                value=["AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N"],
                            ),
                        ],
                    ),
                ],
            ),
            AdvisoryData(
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
                                system=severity_systems.CVSSV3,
                                value="6.7",
                            ),
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV3_VECTOR,
                                value=["AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"],
                            ),
                        ],
                    ),
                ],
            ),
        ]

        found_advisories = to_advisories(raw_data)

        found_advisories = list(map(AdvisoryData.normalized, found_advisories))
        expected_advisories = list(map(AdvisoryData.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
