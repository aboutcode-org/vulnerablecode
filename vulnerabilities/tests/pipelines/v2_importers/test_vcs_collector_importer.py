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

from vulnerabilities.pipelines.v2_importers.vcs_collector_importer import VSCCollectorPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "vcs_collector"


class TestVSCCollectorPipeline(TestCase):
    @patch(
        "vulnerabilities.pipelines.v2_importers.vcs_collector_importer.get_advisory_url",
        return_value="https://mocked.url/advisory",
    )
    @patch("vulnerabilities.pipelines.v2_importers.vcs_collector_importer.Path.rglob")
    def test_fix_commits_data(self, mock_rglob, mock_get_advisory_url):
        pipeline = VSCCollectorPipeline()
        pipeline.vcs_response = SimpleNamespace(dest_dir=TEST_DATA)
        mock_input_file = Path(TEST_DATA) / "fix_commits_test_repo.json"
        mock_rglob.return_value = [mock_input_file]
        expected_file = os.path.join(TEST_DATA, "expected_fix_commits_output.json")
        result = [adv.to_dict() for adv in pipeline.collect_advisories_fix_commits()]
        result.sort(key=lambda x: x["advisory_id"])
        util_tests.check_results_against_json(result, expected_file)

    @patch(
        "vulnerabilities.pipelines.v2_importers.vcs_collector_importer.get_advisory_url",
        return_value="https://mocked.url/advisory",
    )
    @patch("vulnerabilities.pipelines.v2_importers.vcs_collector_importer.Path.rglob")
    def test_issue_prs_data(self, mock_rglob, mock_get_advisory_url):
        pipeline = VSCCollectorPipeline()
        pipeline.vcs_response = SimpleNamespace(dest_dir=TEST_DATA)
        mock_input_file = Path(TEST_DATA) / "pr_issues_test_repo.json"
        mock_rglob.return_value = [mock_input_file]
        expected_file = os.path.join(TEST_DATA, "expected_pr_issues_output.json")
        result = [adv.to_dict() for adv in pipeline.collect_advisories_prs_and_issues()]
        result.sort(key=lambda x: x["advisory_id"])
        util_tests.check_results_against_json(result, expected_file)
