# Author: Navonil Das (@NavonilDas)
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

from django.test import TestCase

from vulnerabilities.importers.npm import parse_advisory_data
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/npm")


class NpmImportTest(TestCase):
    def test_npm_advisories_1(self):
        with open(os.path.join(TEST_DATA, "npm_test_1.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, f"npm-expected_1.json")
        imported_data = parse_advisory_data(mock_response)
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_npm_advisories__2(self):
        with open(os.path.join(TEST_DATA, "npm_test_2.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "npm-expected_2.json")
        imported_data = parse_advisory_data(mock_response)
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_npm_advisories__3(self):
        with open(os.path.join(TEST_DATA, "npm_test_3.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "npm-expected_3.json")
        imported_data = parse_advisory_data(mock_response)
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)
