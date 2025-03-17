#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import os
from unittest import TestCase

import saneyaml

from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/oss_fuzz")


class TestOSSFuzzImporter(TestCase):
    def test_to_advisories1(self):
        with open(os.path.join(TEST_DATA, "oss-fuzz-data1.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "oss-fuzz-data1.yaml-expected.json")
        imported_data = parse_advisory_data(
            mock_response, "oss-fuzz", advisory_url="http://test.com"
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisorie2(self):
        with open(os.path.join(TEST_DATA, "oss-fuzz-data2.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "oss-fuzz-data2.yaml-expected.json")
        imported_data = parse_advisory_data(
            mock_response, "oss-fuzz", advisory_url="http://test.com"
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)
