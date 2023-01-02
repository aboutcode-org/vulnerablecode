#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

from vulnerabilities.importers.elixir_security import ElixirSecurityImporter
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data/elixir_security/")


def test_elixir_process_file():
    path = os.path.join(TEST_DIR, "test_file.yml")
    expected_file = os.path.join(TEST_DIR, f"elixir-expected.json")
    result = [data.to_dict() for data in list(ElixirSecurityImporter().process_file(path))]
    util_tests.check_results_against_json(result, expected_file)
