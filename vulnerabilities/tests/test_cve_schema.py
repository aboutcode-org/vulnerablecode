#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from unittest import TestCase

from vulnerabilities.importers.cve_schema import parse_cve_v5_advisory
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/cve_schema")


class TestCVESchemaV5(TestCase):
    def test_to_advisories1(self):
        with open(os.path.join(TEST_DATA, "vulnrichment-data1.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "vulnrichment-data1-expected.json")
        imported_data = parse_cve_v5_advisory(mock_response, advisory_url="https://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisorie2(self):
        with open(os.path.join(TEST_DATA, "vulnrichment-data2.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "vulnrichment-data2-expected.json")
        imported_data = parse_cve_v5_advisory(mock_response, advisory_url="https://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisorie3(self):
        with open(os.path.join(TEST_DATA, "vulnrichment-data3.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "vulnrichment-data3-expected.json")
        imported_data = parse_cve_v5_advisory(mock_response, advisory_url="https://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories4(self):
        with open(os.path.join(TEST_DATA, "cvelistv5-data1.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "cvelistv5-data1-expected.json")
        imported_data = parse_cve_v5_advisory(mock_response, advisory_url="https://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisorie5(self):
        with open(os.path.join(TEST_DATA, "cvelistv5-data2.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "cvelistv5-data2-expected.json")
        imported_data = parse_cve_v5_advisory(mock_response, advisory_url="https://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisorie6(self):
        with open(os.path.join(TEST_DATA, "cvelistv5-data3.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "cvelistv5-data3-expected.json")
        imported_data = parse_cve_v5_advisory(mock_response, advisory_url="https://test.com")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)
