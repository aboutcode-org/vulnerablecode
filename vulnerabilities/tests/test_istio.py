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
from unittest import mock

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.istio import IstioImporter
from vulnerabilities.importers.istio import IstioImprover
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data/istio")


def test_istio_get_data_from_md():
    path = os.path.join(TEST_DIR, "test_file.md")
    actual_data = IstioImporter().get_data_from_md(path)
    expected_data = {
        "title": "ISTIO-SECURITY-2019-001",
        "subtitle": "Security Bulletin",
        "description": "Incorrect access control.",
        "cves": ["CVE-2019-12243"],
        "cvss": "8.9",
        "vector": "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:H/RL:O/RC:C",
        "releases": [
            "All releases prior to 0.0.9",
            "1.1 to 1.1.15",
            "1.3 to 1.3.1",
            "All releases 1.5.0 and later",
        ],
        "publishdate": "2019-05-28",
    }

    assert expected_data == actual_data


def test_istio_process_file():
    path = os.path.join(TEST_DIR, "test_file.md")
    expected_file = os.path.join(TEST_DIR, f"istio-expected.json")
    result = [data.to_dict() for data in list(IstioImporter().process_file(path))]
    util_tests.check_results_against_json(result, expected_file)


@mock.patch("vulnerabilities.importers.istio.IstioImprover.get_package_versions")
def test_istio_improver(mock_response):
    advisory_file = os.path.join(TEST_DIR, f"istio-expected.json")
    expected_file = os.path.join(TEST_DIR, f"istio-improver-expected.json")
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
    improvers = [IstioImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    util_tests.check_results_against_json(result, expected_file)
