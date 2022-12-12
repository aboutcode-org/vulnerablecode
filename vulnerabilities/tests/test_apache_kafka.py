#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# temporarily import json to create output to analyze
import json
import os

import pytest

from vulnerabilities.importers.apache_kafka import ApacheKafkaImporter

# from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Created cve-list-2022-12-06.html with a full copy of https://raw.githubusercontent.com/apache/kafka-site/asf-site/cve-list.html
TEST_DATA = os.path.join(
    BASE_DIR,
    "test_data/apache_kafka",
)


def test_to_advisory():
    with open(os.path.join(TEST_DATA, "cve-list-2022-12-06.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)
    result = [data.to_dict() for data in advisories]

    # TODO: We need to finish this test including the REGEN step.  2022-12-12 Monday 14:48:05.  Done.
    expected_file = os.path.join(TEST_DATA, f"to-advisory-apache_kafka-expected.json")
    util_tests.check_results_against_json(result, expected_file)

    # We generate these 2 files solely to vet the output and adjust the importer code.
    # with open(os.path.join(TEST_DATA, "jmh-test-01.txt"), "w") as f1:
    #     for advisory_object in result:
    #         f1.write(f"{advisory_object}\n\n")
    #         for k, v in advisory_object.items():
    #             f1.write(f"{k}: {v}\n\n")
    #         f1.write(f"=================================================\n\n")

    # with open(os.path.join(TEST_DATA, "test-advisories.json"), "w", encoding="utf-8") as f:
    #     json.dump(result, f, ensure_ascii=False, indent=4)


# Check for an unknown CVE value.
def to_advisory_changed_cve():
    with open(os.path.join(TEST_DATA, "cve-list-changed-cve.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)


def test_to_advisory_changed_cve_exception():
    with pytest.raises(KeyError) as excinfo:
        to_advisory_changed_cve()

    assert "CVE-2022-34918" in str(excinfo.value)


# Check for an unknown "Versions affected" value.
def to_advisory_changed_versions_affected():
    with open(os.path.join(TEST_DATA, "cve-list-changed-versions-affected.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)


def test_to_advisory_changed_versions_affected_exception():
    with pytest.raises(KeyError) as excinfo:
        to_advisory_changed_versions_affected()

    assert "2.8.0 - 2.8.1, 3.0.0 - 3.0.1, 3.1.0 - 3.1.1, 3.2.0 - 3.2.2" in str(excinfo.value)


# Check for an unknown "Fixed versions" value.
def to_advisory_changed_fixed_versions():
    with open(os.path.join(TEST_DATA, "cve-list-changed-fixed-versions.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)


def test_to_advisory_changed_fixed_versions_exception():
    with pytest.raises(KeyError) as excinfo:
        to_advisory_changed_fixed_versions()

    assert "2.8.2, 3.0.2, 3.1.2, 3.2.4" in str(excinfo.value)
