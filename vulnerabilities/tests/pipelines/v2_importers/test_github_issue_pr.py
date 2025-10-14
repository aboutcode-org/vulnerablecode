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
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from vulnerabilities.pipelines.v2_importers.github_issue_pr import GithubPipelineIssuePR
from vulnerabilities.tests import util_tests


@pytest.fixture
def pipeline():
    pipeline = GithubPipelineIssuePR()
    pipeline.repo_url = "https://github.com/test/repo"
    pipeline.log = MagicMock()
    return pipeline


@pytest.mark.django_db
def test_collect_issues_and_prs(pipeline):
    pipeline.issues = [
        SimpleNamespace(
            title="Fix for CVE-2023-1234 found",
            body="This resolves a security issue",
            html_url="http://example.com/issue1",
        ),
        SimpleNamespace(
            title="No vulnerability mentioned",
            body="This is unrelated",
            html_url="http://example.com/issue2",
        ),
    ]

    pipeline.pull_requestes = [
        SimpleNamespace(
            title="Patch addressing GHSA-zzz-111",
            body="Also fixes PYSEC-2024-5678",
            html_url="http://example.com/pr1",
        )
    ]

    result = pipeline.collect_issues_and_prs()
    expected = {
        "CVE-2023-1234": [("Issue", "http://example.com/issue1")],
        "GHSA-zzz-111": [("PR", "http://example.com/pr1")],
        "PYSEC-2024-5678": [("PR", "http://example.com/pr1")],
    }

    assert result == expected


TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "github_issue_pr"


@pytest.mark.django_db
def test_collect_advisories_from_json():
    input_file = TEST_DATA / "issues_and_pr.json"
    expected_file = TEST_DATA / "expected_advisory_output.json"

    issues_and_prs = json.loads(input_file.read_text(encoding="utf-8"))

    pipeline = GithubPipelineIssuePR()
    pipeline.repo_url = "https://github.com/test/repo"
    pipeline.log = MagicMock()

    pipeline.collect_issues_and_prs = MagicMock(return_value=issues_and_prs)

    result = [adv.to_dict() for adv in pipeline.collect_advisories()]

    util_tests.check_results_against_json(result, expected_file)
