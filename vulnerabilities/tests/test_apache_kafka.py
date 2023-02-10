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

from vulnerabilities.importers.apache_kafka import ApacheKafkaImporter
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TEST_DATA = os.path.join(
    BASE_DIR,
    "test_data/apache_kafka",
)


def test_to_advisory():
    with open(os.path.join(TEST_DATA, "cve-list-2022-12-06.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)
    result = [data.to_dict() for data in advisories]

    expected_file = os.path.join(TEST_DATA, f"to-advisory-apache_kafka-expected.json")
    util_tests.check_results_against_json(result, expected_file)


def to_advisory_changed_cve():
    with open(os.path.join(TEST_DATA, "cve-list-changed-cve.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)


def test_to_advisory_changed_cve_exception():
    with pytest.raises(KeyError) as excinfo:
        to_advisory_changed_cve()

    assert "CVE-2022-34918" in str(excinfo.value)


def to_advisory_changed_versions_affected():
    with open(os.path.join(TEST_DATA, "cve-list-changed-versions-affected.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)


def test_to_advisory_changed_versions_affected_exception():
    with pytest.raises(KeyError) as excinfo:
        to_advisory_changed_versions_affected()

    assert "2.8.0 - 2.8.1, 3.0.0 - 3.0.1, 3.1.0 - 3.1.1, 3.2.0 - 3.2.2" in str(excinfo.value)


def to_advisory_changed_fixed_versions():
    with open(os.path.join(TEST_DATA, "cve-list-changed-fixed-versions.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)


def test_to_advisory_changed_fixed_versions_exception():
    with pytest.raises(KeyError) as excinfo:
        to_advisory_changed_fixed_versions()

    assert "2.8.2, 3.0.2, 3.1.2, 3.2.4" in str(excinfo.value)
