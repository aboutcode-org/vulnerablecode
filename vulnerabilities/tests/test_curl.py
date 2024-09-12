#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from unittest import TestCase
from unittest.mock import patch

from vulnerabilities.importers.curl import get_cwe_from_curl_advisory
from vulnerabilities.importers.curl import parse_advisory_data
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/curl")


class TestCurlImporter(TestCase):
    def test_parse_advisory_data1(self):
        mock_response = load_json(os.path.join(TEST_DATA, "curl_advisory_mock1.json"))
        expected_file = os.path.join(TEST_DATA, "expected_curl_advisory_output1.json")
        result = parse_advisory_data(mock_response)
        result = result.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_advisory_data2(self):
        mock_response = load_json(os.path.join(TEST_DATA, "curl_advisory_mock2.json"))
        expected_file = os.path.join(TEST_DATA, "expected_curl_advisory_output2.json")
        result = parse_advisory_data(mock_response)
        result = result.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_parse_advisory_data3(self):
        mock_response = load_json(os.path.join(TEST_DATA, "curl_advisory_mock3.json"))
        expected_file = os.path.join(TEST_DATA, "expected_curl_advisory_output3.json")
        result = parse_advisory_data(mock_response)
        result = result.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_get_cwe_from_curl_advisory(self):
        assert get_cwe_from_curl_advisory(
            {
                "id": "CURL-CVE-2024-2466",
                "database_specific": {
                    "CWE": {
                        "id": "CWE-297",
                        "desc": "Improper Validation of Certificate with Host Mismatch",
                    },
                },
            }
        ) == [297]

        mock_advisory = [
            {
                "id": "CURL-CVE-XXXX-XXXX",
                "database_specific": {"CWE": {"id": "CWE-111111111", "desc": "Invalid weaknesses"}},
            },
            {
                "id": "CURL-CVE-2024-2466",
                "database_specific": {
                    "CWE": {"id": "CWE-311", "desc": "Missing Encryption of Sensitive Data"},
                },
            },
        ]
        mock_cwe_list = []
        for advisory in mock_advisory:
            mock_cwe_list.extend(get_cwe_from_curl_advisory(advisory))
        assert mock_cwe_list == [311]
