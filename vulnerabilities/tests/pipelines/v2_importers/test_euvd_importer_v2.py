#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import patch

from vulnerabilities.pipelines.v2_importers.euvd_importer import EUVDImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "euvd"


class TestEUVDImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.euvd_importer.requests.get")
    def test_collect_advisories(self, mock_get):
        """Test collecting and parsing advisories from test data"""
        sample1_path = TEST_DATA / "euvd_sample1.json"
        sample2_path = TEST_DATA / "euvd_sample2.json"

        sample1 = json.loads(sample1_path.read_text(encoding="utf-8"))
        sample2 = json.loads(sample2_path.read_text(encoding="utf-8"))

        mock_responses = [
            Mock(status_code=200, json=lambda: sample1),
            Mock(status_code=200, json=lambda: sample1),
            Mock(status_code=200, json=lambda: sample2),
        ]
        mock_get.side_effect = mock_responses

        pipeline = EUVDImporterPipeline()
        advisories = [data.to_dict() for data in list(pipeline.collect_advisories())]

        expected_file = TEST_DATA / "euvd-expected.json"
        util_tests.check_results_against_json(advisories, expected_file)

    def test_get_scoring_system(self):
        """Test CVSS version to scoring system mapping"""
        pipeline = EUVDImporterPipeline()

        system_v4 = pipeline.get_scoring_system("4.0")
        assert system_v4 is not None
        assert system_v4.identifier == "cvssv4"

        system_v31 = pipeline.get_scoring_system("3.1")
        assert system_v31 is not None
        assert system_v31.identifier == "cvssv3.1"

        system_v3 = pipeline.get_scoring_system("3.0")
        assert system_v3 is not None
        assert system_v3.identifier == "cvssv3"

        system_v2 = pipeline.get_scoring_system("2.0")
        assert system_v2 is not None
        assert system_v2.identifier == "cvssv2"

        system_unknown = pipeline.get_scoring_system("unknown")
        assert system_unknown is None

    @patch("vulnerabilities.pipelines.v2_importers.euvd_importer.requests.get")
    def test_advisories_count(self, mock_get):
        """Test counting advisories"""
        sample_data = {"items": [{"id": "1"}, {"id": "2"}, {"id": "3"}], "total": 3}
        mock_responses = [
            Mock(status_code=200, json=lambda: sample_data),
            Mock(status_code=200, json=lambda: sample_data),
        ]
        mock_get.side_effect = mock_responses

        pipeline = EUVDImporterPipeline()
        count = pipeline.advisories_count()

        assert count == 3
