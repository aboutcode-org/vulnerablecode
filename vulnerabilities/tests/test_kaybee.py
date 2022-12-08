#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

from vulnerabilities.importers.kaybee import yaml_file_to_advisory
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "kaybee")


def test_parse_yaml_file():
    response_file = os.path.join(TEST_DATA, "statement.yaml")
    expected_file = os.path.join(TEST_DATA, "statement-expected.json")
    advisory = yaml_file_to_advisory(response_file)
    util_tests.check_results_against_json(advisory.to_dict(), expected_file)
