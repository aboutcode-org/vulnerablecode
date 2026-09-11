#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

from vulnerabilities.pipelines.v2_importers.eclipse_importer import EclipseImporterPipeline
from vulnerabilities.pipelines.v2_importers.eclipse_importer import parse_advisory
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import load_json

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "eclipse"

SAMPLE_DATA = load_json(TEST_DATA / "eclipse_api_sample.json")


def test_parse_advisories():
    results = [parse_advisory(entry).to_dict() for entry in SAMPLE_DATA]
    expected_file = TEST_DATA / "expected_eclipse_output.json"
    util_tests.check_results_against_json(results, expected_file)


class TestEclipseImporterPipeline(TestCase):
    def setUp(self):
        self.pipeline = EclipseImporterPipeline()
        self.pipeline.advisories_data = SAMPLE_DATA

    def test_advisories_count(self):
        assert self.pipeline.advisories_count() == 3

    def test_collect_advisories_yields_all_valid(self):
        advisories = list(self.pipeline.collect_advisories())
        assert len(advisories) == 3

    @patch("vulnerabilities.pipelines.v2_importers.eclipse_importer.requests.get")
    def test_fetch_stores_advisories_data(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = SAMPLE_DATA
        mock_get.return_value = mock_resp
        self.pipeline.fetch()
        assert self.pipeline.advisories_data == SAMPLE_DATA
