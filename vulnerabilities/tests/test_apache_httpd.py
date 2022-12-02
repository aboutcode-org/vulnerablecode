#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from unittest import TestCase

import pytest
from univers.version_constraint import VersionConstraint
from univers.version_range import GenericVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importers.apache_httpd import ApacheHTTPDImporter
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/apache_httpd")


def test_to_version_ranges():
    data = [
        {
            "version_affected": "?=",
            "version_value": "1.3.0",
        },
        {
            "version_affected": "=",
            "version_value": "1.3.1",
        },
        {
            "version_affected": "<=",
            "version_value": "2.3.4",
        },
    ]
    fixed_versions = ["1.3.2"]
    affected_version_range = ApacheHTTPDImporter().to_version_ranges(data, fixed_versions)

    assert (
        GenericVersionRange(
            constraints=(
                VersionConstraint(comparator="=", version=SemverVersion(string="1.3.1")),
                VersionConstraint(comparator="<=", version=SemverVersion(string="2.3.4")),
                VersionConstraint(comparator="!=", version=SemverVersion(string="1.3.2")),
            )
        )
        == affected_version_range
    )


def unknown_comparator():
    data = [
        {
            "version_affected": "?=",
            "version_value": "1.3.0",
        },
        {
            "version_affected": "=",
            "version_value": "1.3.1",
        },
        {
            "version_affected": "#=",
            "version_value": "2.3.4",
        },
    ]
    fixed_versions = ["1.3.2"]
    affected_version_range = ApacheHTTPDImporter().to_version_ranges(data, fixed_versions)


def test_unknown_comparator_exception():
    with pytest.raises(ValueError) as excinfo:
        unknown_comparator()

    assert "unknown comparator found! #=" in str(excinfo.value)


def test_to_advisory_CVE_1999_1199():
    with open(os.path.join(TEST_DATA, "CVE-1999-1199.json")) as f:
        data = json.load(f)

    advisories = ApacheHTTPDImporter().to_advisory(data)
    result = advisories.to_dict()
    expected_file = os.path.join(TEST_DATA, f"to-advisory-CVE-1999-1199-apache-httpd-expected.json")
    util_tests.check_results_against_json(result, expected_file)


def test_to_advisory_CVE_2021_44224():
    with open(os.path.join(TEST_DATA, "CVE-2021-44224.json")) as f:
        data = json.load(f)

    advisories = ApacheHTTPDImporter().to_advisory(data)
    result = advisories.to_dict()
    expected_file = os.path.join(
        TEST_DATA, f"to-advisory-CVE-2021-44224-apache-httpd-expected.json"
    )
    util_tests.check_results_against_json(result, expected_file)


def test_to_advisory_CVE_2017_9798():
    with open(os.path.join(TEST_DATA, "CVE-2017-9798.json")) as f:
        data = json.load(f)

    advisories = ApacheHTTPDImporter().to_advisory(data)
    result = advisories.to_dict()
    expected_file = os.path.join(TEST_DATA, f"to-advisory-CVE-2017-9798-apache-httpd-expected.json")
    util_tests.check_results_against_json(result, expected_file)
