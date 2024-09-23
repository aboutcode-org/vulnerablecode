#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from pathlib import Path
from unittest import TestCase

import saneyaml

from vulnerabilities.importers.osv import parse_advisory_data
from vulnerabilities.tests import util_tests

TEST_DATA = data = Path(__file__).parent.parent / "test_data" / "pypa"


class TestPyPaImporterPipeline(TestCase):
    def test_to_advisories_with_summary(self):
        pypa_advisory_path = TEST_DATA / "pypa_test.yaml"

        mock_response = saneyaml.load(pypa_advisory_path.read_text())
        expected_file = os.path.join(TEST_DATA, "pypa-expected.json")
        imported_data = parse_advisory_data(
            mock_response,
            ["pypi"],
            "https://github.com/pypa/advisory-database/blob/main/vulns/pypa-expected.json",
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)
