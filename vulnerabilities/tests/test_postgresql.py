#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

import pytest

from vulnerabilities.importers.postgresql import to_advisories
from vulnerabilities.models import Package
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(
    BASE_DIR,
    "test_data/postgresql",
)


def test_to_advisories():
    with open(os.path.join(TEST_DATA, "advisories.html")) as f:
        raw_data = f.read()
    advisories = to_advisories(raw_data)
    result = [data.to_dict() for data in advisories]
    expected_file = os.path.join(TEST_DATA, f"parse-advisory-postgresql-expected.json")
    util_tests.check_results_against_json(result, expected_file)


@pytest.mark.django_db
def test_get_or_create_from_purl():
    p1 = "pkg:generic/postgres"
    p2 = "pkg:generic/postgres?foo=bar"
    res1 = Package.objects.get_or_create_from_purl(p1)
    res2 = Package.objects.get_or_create_from_purl(p2)
    res3 = Package.objects.get_or_create_from_purl(p1)
