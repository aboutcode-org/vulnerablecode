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
from unittest.mock import patch

import pytest

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.apache_kafka import ApacheKafkaImporter
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import ApacheKafkaImprover
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


@patch("vulnerabilities.improvers.valid_versions.ApacheKafkaImprover.get_package_versions")
def test_apache_tomcat_improver(mock_response):
    advisory_file = os.path.join(TEST_DATA, f"to-advisory-apache_kafka-expected.json")
    with open(advisory_file) as exp:
        advisories = [AdvisoryData.from_dict(adv) for adv in (json.load(exp))]
    mock_response.return_value = [
        "1.1.0",
        "1.1.1",
        "1.1.2",
        "1.1.3",
        "1.1.4",
        "1.1.5",
        "1.1.6",
        "1.1.7",
        "1.1.8",
    ]
    improvers = [ApacheKafkaImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    expected_file = os.path.join(TEST_DATA, f"apache-kafka-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)


def to_advisory_changed_cve():
    with open(os.path.join(TEST_DATA, "cve-list-changed-cve.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)


def to_advisory_changed_versions_affected():
    with open(os.path.join(TEST_DATA, "cve-list-changed-versions-affected.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)


def to_advisory_changed_fixed_versions():
    with open(os.path.join(TEST_DATA, "cve-list-changed-fixed-versions.html")) as f:
        raw_data = f.read()
    advisories = ApacheKafkaImporter().to_advisory(raw_data)
