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
from unittest.mock import patch

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.apache_tomcat import ApacheTomcatImporter
from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.package_managers import PackageVersion
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/apache_tomcat")

security_updates_home = "https://tomcat.apache.org/security"


# This test is temporary -- just for running apache_tomcat.py using all HTML report pages.
# Will replace with a REGEN-based test as with apache_httpd and postgresql.
def test_updated_advisories():
    returned_advisories = ApacheTomcatImporter().updated_advisories()


def test_fetch_links():
    retrieved_links = ApacheTomcatImporter().fetch_links(security_updates_home)

    assert retrieved_links == [
        "https://tomcat.apache.org/security-10.html",
        "https://tomcat.apache.org/security-9.html",
        "https://tomcat.apache.org/security-8.html",
        "https://tomcat.apache.org/security-7.html",
        "https://tomcat.apache.org/security-6.html",
        "https://tomcat.apache.org/security-5.html",
        "https://tomcat.apache.org/security-4.html",
        "https://tomcat.apache.org/security-3.html",
    ]


def test_to_version_ranges_test():
    versions_data = [
        "1.0.0-2.0.0",
        "3.2.2-3.2.3?",
        "3.3a-3.3.1",
        "9.0.0.M1 to 9.0.0.M9",
        "10.1.0-M1 to 10.1.0-M16",
    ]
    fixed_versions = ["3.0.0", "3.3.1a"]

    expected_versions_data = "vers:maven/>=1.0.0|<=2.0.0|!=3.0.0|>=3.2.2|<=3.2.3?|>=3.3a|<=3.3.1|!=3.3.1a|>=9.0.0.M1|<=9.0.0.M9|>=10.1.0-M1|<=10.1.0-M16"

    expected_MavenVersionRange_versions_data = MavenVersionRange(
        constraints=(
            VersionConstraint(comparator=">=", version=MavenVersion(string="1.0.0")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="2.0.0")),
            VersionConstraint(comparator="!=", version=MavenVersion(string="3.0.0")),
            VersionConstraint(comparator=">=", version=MavenVersion(string="3.2.2")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="3.2.3?")),
            VersionConstraint(comparator=">=", version=MavenVersion(string="3.3a")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="3.3.1")),
            VersionConstraint(comparator="!=", version=MavenVersion(string="3.3.1a")),
            VersionConstraint(comparator=">=", version=MavenVersion(string="9.0.0.M1")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="9.0.0.M9")),
            VersionConstraint(comparator=">=", version=MavenVersion(string="10.1.0-M1")),
            VersionConstraint(comparator="<=", version=MavenVersion(string="10.1.0-M16")),
        )
    )

    converted_versions_data = ApacheTomcatImporter().to_version_ranges(
        versions_data, fixed_versions
    )

    # print("\nvers_test = {}\n".format(MavenVersionRange.from_string("vers:maven/>=1.0.0|<=2.0.0")))
    # print("\nconverted_versions_data = {}\n".format(converted_versions_data))

    assert expected_MavenVersionRange_versions_data == converted_versions_data
    assert MavenVersionRange.from_string(expected_versions_data) == converted_versions_data
