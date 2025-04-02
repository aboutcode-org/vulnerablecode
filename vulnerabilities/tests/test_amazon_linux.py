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

from bs4 import BeautifulSoup

from vulnerabilities.importers.amazon_linux import process_advisory_data
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/amazon_linux")


class TestAmazonLinuxImporter(TestCase):
    def test_process_advisory_data1(self):
        with open(
            os.path.join(TEST_DATA, "amazon_linux_advisory_test1.html"), "r", encoding="utf-8"
        ) as file:
            html_content = file.read()
        result = process_advisory_data(
            "ALAS-2024-1943", html_content, "https://alas.aws.amazon.com/ALAS-2024-1943.html"
        ).to_dict()
        expected_file = os.path.join(TEST_DATA, "amazon_linux_expected1.json")
        util_tests.check_results_against_json(result, expected_file)

    def test_process_advisory_data2(self):
        with open(
            os.path.join(TEST_DATA, "amazon_linux_advisory_test2.html"), "r", encoding="utf-8"
        ) as file:
            html_content = file.read()
        result = process_advisory_data(
            "ALAS-2024-2628", html_content, "https://alas.aws.amazon.com/AL2/ALAS-2024-2628.html"
        ).to_dict()
        expected_file = os.path.join(TEST_DATA, "amazon_linux_expected2.json")
        util_tests.check_results_against_json(result, expected_file)

    def test_process_advisory_data3(self):
        with open(
            os.path.join(TEST_DATA, "amazon_linux_advisory_test3.html"), "r", encoding="utf-8"
        ) as file:
            html_content = file.read()
        result = process_advisory_data(
            "ALAS-2024-676", html_content, "https://alas.aws.amazon.com/AL2023/ALAS-2024-676.html"
        ).to_dict()
        expected_file = os.path.join(TEST_DATA, "amazon_linux_expected3.json")
        util_tests.check_results_against_json(result, expected_file)
