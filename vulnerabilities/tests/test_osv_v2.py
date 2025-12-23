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

import saneyaml

from vulnerabilities.importers.osv_v2 import parse_advisory_data_v3
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/osv_test")


class TestOSVImporter(TestCase):
    def test_to_advisories_github1(self):
        with open(os.path.join(TEST_DATA, "github/github-1.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github/github-expected-1.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "maven", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_github2(self):
        with open(os.path.join(TEST_DATA, "github/github-2.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github/github-expected-2.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "packagist", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_oss_fuzz1(self):
        with open(os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-1.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-expected-1.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "generic", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_oss_fuzz2(self):
        with open(os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-2.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-expected-2.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "generic", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa1(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-1.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-1.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa2(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-2.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-2.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa3(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-3.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-3.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa4(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-4.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-4.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa5(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-5.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-5.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa6(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-6.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-6.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)
