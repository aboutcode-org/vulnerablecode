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

from vulnerabilities.pipelines.v2_importers.tuxcare_importer import TuxCareImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "tuxcare"


class TestTuxCareImporterPipeline(TestCase):
    @patch("vulnerabilities.pipelines.v2_importers.tuxcare_importer.fetch_response")
    def test_collect_advisories(self, mock_fetch):
        sample_path = TEST_DATA / "data.json"
        sample_data = json.loads(sample_path.read_text(encoding="utf-8"))

        mock_fetch.return_value = Mock(json=lambda: sample_data)

        pipeline = TuxCareImporterPipeline()
        pipeline.fetch()

        advisories = [data.to_dict() for data in list(pipeline.collect_advisories())]

        expected_file = TEST_DATA / "expected.json"
        util_tests.check_results_against_json(advisories, expected_file)

        assert pipeline.advisories_count() == 5
