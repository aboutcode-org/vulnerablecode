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

from vulnerabilities.importers.debian import DebianBasicImprover
from vulnerabilities.importers.debian import DebianImporter
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data")


@patch("vulnerabilities.importers.debian.DebianImporter.get_response")
def test_debian_importer(mock_response):
    with open(os.path.join(TEST_DATA, "debian.json")) as f:
        mock_response.return_value = json.load(f)

    expected_file = os.path.join(TEST_DATA, f"debian-expected.json")
    result = [data.to_dict() for data in list(DebianImporter().advisory_data())]
    util_tests.check_results_against_json(result, expected_file)


@patch("vulnerabilities.importers.debian.DebianImporter.get_response")
def test_debian_improver(mock_response):
    with open(os.path.join(TEST_DATA, "debian.json")) as f:
        mock_response.return_value = json.load(f)
    advisories = list(DebianImporter().advisory_data())
    result = []
    improvers = [DebianBasicImprover(), DefaultImprover()]
    for improver in improvers:
        for advisory in advisories:
            for data in improver.get_inferences(advisory_data=advisory):
                result.append(data.to_dict())
    expected_file = os.path.join(TEST_DATA, f"debian-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)
