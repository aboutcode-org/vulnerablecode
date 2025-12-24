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
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from vulnerabilities.pipelines.v2_importers.project_kb_msr2019_importer import (
    ProjectKBMSR2019Pipeline,
)
from vulnerabilities.pipelines.v2_importers.project_kb_statements_importer import (
    ProjectKBStatementsPipeline,
)
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "project-kb"


class TestProjectKbImporterPipeline(TestCase):
    def test_project_kb_msr2019_data(self):
        pipeline = ProjectKBMSR2019Pipeline()
        pipeline.vcs_response = SimpleNamespace(dest_dir=TEST_DATA)
        expected_file = os.path.join(TEST_DATA, "kbmsr2019-expected.json")
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]
        result.sort(key=lambda x: x["advisory_id"])
        util_tests.check_results_against_json(result, expected_file)

    @patch(
        "vulnerabilities.pipelines.v2_importers.project_kb_statements_importer.get_advisory_url",
        return_value="https://mocked.url/advisory",
    )
    def test_project_kb_statements_data(self, mock_get_advisory_url):
        pipeline = ProjectKBStatementsPipeline()
        pipeline.vcs_response = SimpleNamespace(dest_dir=TEST_DATA)
        expected_file = os.path.join(TEST_DATA, "kb-statements-expected.json")
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]
        result.sort(key=lambda x: x["advisory_id"])
        util_tests.check_results_against_json(result, expected_file)
