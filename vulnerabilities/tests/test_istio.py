#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

from vulnerabilities.importers.istio import IstioImporter
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
        "releases": ["1.1 to 1.1.15", "1.2 to 1.2.6", "1.3 to 1.3.1"],
        "publishdate": "2019-05-28",
    }

    assert expected_data == actual_data


def test_istio_process_file():
    path = os.path.join(TEST_DIR, "test_file.md")
    expected_file = os.path.join(TEST_DIR, f"istio-expected.json")
    result = [data.to_dict() for data in list(IstioImporter().process_file(path))]
    util_tests.check_results_against_json(result, expected_file)
