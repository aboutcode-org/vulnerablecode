# Author: Navonil Das (@NavonilDas)
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importers.npm import NpmImporter
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


def test_npm_importer():
    file = os.path.join(TEST_DATA, "npm_sample.json")
    result = [adv.to_dict() for adv in NpmImporter().to_advisory_data(file=file)]
    expected_file = os.path.join(TEST_DATA, f"parse-advisory-npm-expected.json")
    util_tests.check_results_against_json(result, expected_file)


def test_get_affected_package():
    file = os.path.join(TEST_DATA, "npm_sample.json")
    data = load_json(file)
    assert AffectedPackage(
        package=PackageURL(
            type="npm", namespace=None, name="npm", version=None, qualifiers={}, subpath=None
        ),
        affected_version_range=NpmVersionRange(
            constraints=(VersionConstraint(comparator="<", version=SemverVersion(string="1.3.3")),)
        ),
        fixed_version=SemverVersion(string="1.3.3"),
    ) == NpmImporter().get_affected_package(data, "npm")
