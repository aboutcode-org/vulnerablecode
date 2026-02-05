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
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from vulnerabilities.pipes.vcs_collector_utils import CollectVCSFixCommitPipeline
from vulnerabilities.tests import util_tests


@pytest.fixture
def pipeline():
    pipeline = CollectVCSFixCommitPipeline()
    pipeline.repo_url = "https://github.com/test/repo"
    pipeline.pipeline_id = "collect_repo_fix_commits"
    pipeline.log = MagicMock()
    return pipeline


def test_classify_commit_type_extracts_ids(pipeline):
    class DummyCommit:
        message = "Fix for CVE-2023-1234 and GHSA-2479-qvv7-47qq"

    result = pipeline.extract_vulnerability_id(DummyCommit)
    assert result == ["CVE-2023-1234", "GHSA-2479-qvv7-47qq"]


@patch("vulnerabilities.pipes.vcs_collector_utils.Repo")
def test_collect_fix_commits_groups_by_vuln(mock_repo, pipeline):
    commit1 = MagicMock(message="Fix CVE-2021-0001", hexsha="abc123")
    commit2 = MagicMock(message="Patch GHSA-f72r-2h5j-7639", hexsha="def456")
    commit3 = MagicMock(message="Unrelated change", hexsha="ghi789")

    pipeline.repo = MagicMock()
    pipeline.repo.iter_commits.return_value = [commit1, commit2, commit3]

    pipeline.classify_commit_type = MagicMock(
        side_effect=lambda c: (
            ["CVE-2021-0001"]
            if "CVE" in c.message
            else ["GHSA-dead-beef-baad"]
            if "GHSA" in c.message
            else []
        )
    )

    grouped = pipeline.collect_fix_commits()

    expected = {
        "CVE-2021-0001": [("abc123", "Fix CVE-2021-0001")],
        "GHSA-f72r-2h5j-7639": [("def456", "Patch GHSA-f72r-2h5j-7639")],
    }

    assert grouped == expected


TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "fix_commits"


class TestRepoFixCommitPipeline(TestCase):
    def test_collect_advisories_from_json(self):
        input_file = TEST_DATA / "grouped_commits_input.json"
        expected_file = TEST_DATA / "expected_linux_advisory_output.json"

        grouped_commits = json.loads(input_file.read_text(encoding="utf-8"))

        pipeline = CollectVCSFixCommitPipeline()
        pipeline.repo_url = "https://github.com/test/repo"
        pipeline.log = MagicMock()
        pipeline.collect_fix_commits = MagicMock(return_value=grouped_commits)

        result = [adv.to_dict() for adv in pipeline.collect_advisories()]

        util_tests.check_results_against_json(result, expected_file, True)


@pytest.mark.parametrize(
    "commit_message, expected_ids",
    [
        ("Fix CVE-2023-12345 buffer overflow", ["CVE-2023-12345"]),
        ("Address GHSA-4486-gxhx-5mg7 report", ["GHSA-4486-gxhx-5mg7"]),
        (
            "Fix CVE-2023-1111 and GHSA-gch2-phqh-fg9q in kernel",
            ["CVE-2023-1111", "GHSA-gch2-phqh-fg9q"],
        ),
        ("Refactor logging system with no security ID", []),
    ],
)
def test_classify_commit_type_detects_vuln_ids(pipeline, commit_message, expected_ids):
    """Ensure classify_commit_type correctly extracts vulnerability IDs."""

    class DummyCommit:
        def __init__(self, message):
            self.message = message

    commit = DummyCommit(commit_message)
    result = pipeline.extract_vulnerability_id(commit)

    assert result == expected_ids, f"Unexpected result for message: {commit_message}"


def test_classify_commit_type_case_insensitive(pipeline):
    """Ensure pattern matching is case-insensitive."""

    class DummyCommit:
        message = "fix CVE-2022-9999 and GHSA-gqgv-6jq5-jjj9"

    result = pipeline.extract_vulnerability_id(DummyCommit)
    assert result == ["CVE-2022-9999", "GHSA-gqgv-6jq5-jjj9"]
