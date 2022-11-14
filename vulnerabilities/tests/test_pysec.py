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
from unittest import TestCase

from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/pysec")


class TestPyPIImporter(TestCase):
    def test_to_advisories_with_summary(self):
        with open(os.path.join(TEST_DATA, "pysec-advisories_with_summary.json")) as f:
            mock_response = json.load(f)
        results = parse_advisory_data(mock_response, "pypi").to_dict()

        expected_file = os.path.join(TEST_DATA, "pysec-advisories_with_summary-expected.json")
        util_tests.check_results_against_json(
            results=results,
            expected_file=expected_file,
            regen=util_tests.VULNERABLECODE_REGEN_TEST_FIXTURES,
        )

    def test_to_advisories_without_summary(self):
        with open(os.path.join(TEST_DATA, "pysec-advisories_without_summary.json")) as f:
            mock_response = json.load(f)

        results = parse_advisory_data(mock_response, "pypi").to_dict()

        expected_file = os.path.join(TEST_DATA, "pysec-advisories_without_summary-expected.json")
        util_tests.check_results_against_json(
            results=results,
            expected_file=expected_file,
            regen=util_tests.VULNERABLECODE_REGEN_TEST_FIXTURES,
        )
