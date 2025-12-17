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

from vulnerabilities.pipelines.v2_importers.project_kb_importer import ProjectKBPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "kbmsr2019"


class TestProjectKbImporterPipeline(TestCase):
    @patch(
        "vulnerabilities.pipelines.v2_importers.project_kb_importer.get_advisory_url",
        return_value="https://mocked.url/advisory",
    )
    def test_project_kb_data(self, mock_get_advisory_url):
        pipeline = ProjectKBPipeline()
        pipeline.vuln_data_branch_vcs = SimpleNamespace(dest_dir=TEST_DATA)
        pipeline.main_branch_vcs = SimpleNamespace(dest_dir=TEST_DATA)
        expected_file = os.path.join(TEST_DATA, "kbmsr2019-expected.json")
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]
        result.sort(key=lambda x: x["advisory_id"])
        util_tests.check_results_against_json(result, expected_file)
