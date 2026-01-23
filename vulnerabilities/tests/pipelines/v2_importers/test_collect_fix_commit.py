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
from packageurl import PackageURL

from vulnerabilities.pipelines.v2_importers.collect_repo_fix_commits import (
    CollectRepoFixCommitPipeline,
)
from vulnerabilities.tests import util_tests


@pytest.fixture
def pipeline():
    pipeline = CollectRepoFixCommitPipeline()
    pipeline.repo_url = "https://github.com/test/repo"
    pipeline.log = MagicMock()
    return pipeline


def test_classify_commit_type_extracts_ids(pipeline):
    class DummyCommit:
        message = "Fix for CVE-2023-1234 and GHSA-2479-qvv7-47qq"

    result = pipeline.extract_vulnerability_id(DummyCommit)
    assert result == ["CVE-2023-1234", "GHSA-2479-qvv7-47qq"]


@patch("vulnerabilities.pipelines.v2_importers.collect_repo_fix_commits.Repo")
def test_collect_fix_commits_groups_by_vuln(mock_repo, pipeline):
    commit1 = MagicMock(message="Fix CVE-2021-0001", hexsha="abc123")
    commit2 = MagicMock(message="Patch GHSA-dead-beef-baad", hexsha="def456")
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
        "GHSA-dead-beef-baad": [("def456", "Patch GHSA-dead-beef-baad")],
    }

    assert grouped == expected


TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "fix_commits"


class TestRepoFixCommitPipeline(TestCase):
    def test_collect_advisories_from_json(self):
        input_file = TEST_DATA / "grouped_commits_input.json"
        expected_file = TEST_DATA / "expected_linux_advisory_output.json"

        grouped_commits = json.loads(input_file.read_text(encoding="utf-8"))

        pipeline = CollectRepoFixCommitPipeline()
        pipeline.repo_url = "https://github.com/test/repo"
        pipeline.purl = PackageURL.from_string("pkg:generic/test")
        pipeline.log = MagicMock()
        pipeline.collect_fix_commits = MagicMock(return_value=grouped_commits)

        result = [adv.to_dict() for adv in pipeline.collect_advisories()]

        util_tests.check_results_against_json(result, expected_file, True)


@pytest.mark.parametrize(
    "commit_message, expected_ids",
    [
        ("Fix CVE-2023-12345 buffer overflow", ["CVE-2023-12345"]),
        ("Address GHSA-abcd-1234-efgh report", ["GHSA-abcd-1234-efgh"]),
        ("Python security PYSEC-2021-12345 fix", ["PYSEC-2021-12345"]),
        ("Xen XSA-43 security update", ["XSA-43"]),
        (
            "Fix CVE-2023-1111 and GHSA-aaaa-bbbb-cccc in kernel",
            ["CVE-2023-1111", "GHSA-aaaa-bbbb-cccc"],
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
        message = "fix cVe-2022-9999 and ghSa-dead-beef-baad"

    result = pipeline.extract_vulnerability_id(DummyCommit)
    assert any("CVE-2022-9999" in r.upper() for r in result)
    assert any("GHSA-DEAD-BEEF-BAAD" in r.upper() for r in result)
