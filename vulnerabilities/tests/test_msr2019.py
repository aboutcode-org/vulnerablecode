#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import csv
import os

from vulnerabilities.importers.project_kb_msr2019 import ProjectKBMSRImporter
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data/kbmsr2019")


def test_kbmsr_to_advisories():
    TEST_DATA = os.path.join(TEST_DIR, "test_msr_data.csv")
    with open(TEST_DATA) as f:
        lines = [l for l in f.readlines()]
        test_data = csv.reader(lines)
    expected_file = os.path.join(TEST_DIR, f"kbmsr2019-expected.json")
    result = [data.to_dict() for data in list(ProjectKBMSRImporter().to_advisories(test_data))]
    util_tests.check_results_against_json(result, expected_file)
