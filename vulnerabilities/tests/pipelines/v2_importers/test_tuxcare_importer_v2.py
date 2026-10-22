#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from io import BytesIO
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import patch
from zipfile import ZipFile

from vulnerabilities.pipelines.v2_importers.tuxcare_importer import TuxCareImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "tuxcare"


class TestTuxCareImporterPipeline(TestCase):
    """Tests for TuxCareImporterPipeline using OSV feed data."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        zip_buffer = BytesIO()
        with ZipFile(zip_buffer, mode="w") as zip_file:
            for json_file in sorted(TEST_DATA.glob("CLSA-*.json")):
                zip_file.writestr(json_file.name, json_file.read_bytes())
        cls.sample_zip = zip_buffer.getvalue()

    @patch("requests.get")
    def test_fetch_zip(self, mock_get):
        mock_get.return_value = Mock(content=self.sample_zip)

        pipeline = TuxCareImporterPipeline()
        pipeline.fetch_zip()

        mock_get.assert_called_once_with(pipeline.url)
        self.assertEqual(pipeline.advisory_zip, self.sample_zip)

    def test_advisories_count(self):
        pipeline = TuxCareImporterPipeline()
        pipeline.advisory_zip = self.sample_zip

        self.assertEqual(pipeline.advisories_count(), 6)

    def test_collect_advisories(self):
        pipeline = TuxCareImporterPipeline()
        pipeline.advisory_zip = self.sample_zip

        advisories = [data.to_dict() for data in pipeline.collect_advisories()]
        advisories = sorted(advisories, key=lambda a: a["advisory_id"])

        expected_file = TEST_DATA / "expected.json"
        util_tests.check_results_against_json(advisories, expected_file)
        self.assertEqual(len(advisories), 6)
