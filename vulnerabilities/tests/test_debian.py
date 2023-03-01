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
from vulnerabilities.importers.debian import DebianImporter
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import DebianBasicImprover
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


@patch("vulnerabilities.improvers.valid_versions.DebianBasicImprover.get_package_versions")
def test_debian_improver(mock_response):
    advisory_file = os.path.join(TEST_DATA, f"debian-expected.json")
    with open(advisory_file) as exp:
        advisories = [AdvisoryData.from_dict(adv) for adv in (json.load(exp))]
    mock_response.return_value = [
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
    improvers = [DebianBasicImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    expected_file = os.path.join(TEST_DATA, f"debian-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)
