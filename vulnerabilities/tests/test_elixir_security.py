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
from unittest.mock import patch

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.elixir_security import ElixirSecurityImporter
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import ElixirImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data/elixir_security/")


def test_elixir_process_file():
    path = os.path.join(TEST_DIR, "test_file.yml")
    expected_file = os.path.join(TEST_DIR, f"elixir-expected.json")
    result = [data.to_dict() for data in list(ElixirSecurityImporter().process_file(path))]
    util_tests.check_results_against_json(result, expected_file)


@patch("vulnerabilities.improvers.valid_versions.ElixirImprover.get_package_versions")
def test_elixir_improver(mock_response):
    advisory_file = os.path.join(TEST_DIR, f"elixir-expected.json")
    with open(advisory_file) as exp:
        advisories = [AdvisoryData.from_dict(adv) for adv in (json.load(exp))]
    mock_response.return_value = [
        "0.1.0",
        "0.5.6",
        "0.5.2",
        "1.1.0",
        "1.1.1",
        "1.1.2",
        "1.1.3",
        "1.1.4",
        "1.1.5",
        "1.1.6",
        "1.1.7",
        "1.1.8",
    ]
    improvers = [ElixirImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    expected_file = os.path.join(TEST_DIR, f"elixir-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)
