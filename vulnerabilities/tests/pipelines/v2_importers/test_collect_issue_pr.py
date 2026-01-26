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

from vulnerabilities.pipelines import GitHubCollector
from vulnerabilities.pipelines import GitLabCollector
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "collect_issue_pr"


@pytest.mark.django_db
def test_collect_github_issues_and_prs():
    pipeline = GitHubCollector()
    pipeline.issues = [
        SimpleNamespace(
            title="Fix the CVE-2023-1234 found",
            body="This resolves a security issue",
            html_url="https://github.com/issue1",
        ),
        SimpleNamespace(
            title="vulnerability 1",
            body="Fix CVE-2023-124",
            html_url="https://github.com/issue2",
        ),
        SimpleNamespace(
            title="vulnerability 2",
            body="vulnerability 2",
            html_url="https://github.com/issue3",
        ),
    ]

    pipeline.prs = [
        SimpleNamespace(
            title="Patch addressing CVE-2023-1234",
            body="Also fixes CVE-2023-1234",
            html_url="https://github.com/pr1",
        )
    ]

    pipeline.collect_items()
    expected = {
        "CVE-2023-1234": [
            ("Issue", "https://github.com/issue1"),
            ("Issue", "https://github.com/pr1"),
            ("Issue", "https://github.com/pr1"),
        ],
        "CVE-2023-124": [("Issue", "https://github.com/issue2")],
    }

    assert pipeline.collected_items == expected


@pytest.mark.django_db
def test_collect_gitlab_issues_and_prs():
    pipeline = GitLabCollector()
    pipeline.issues = [
        {
            "title": "vulnerability CVE-2024-1234",
            "description": "vulnerability 1",
            "web_url": "https://github.com/issue1",
        },
    ]

    pipeline.prs = [
        {
            "title": "Patch addressing",
            "description": "Also fixes CVE-2023-1234",
            "web_url": "https://github.com/pr1",
        }
    ]

    pipeline.collect_items()
    expected = {
        "CVE-2024-1234": [("Issue", "https://github.com/issue1")],
        "CVE-2023-1234": [("PR", "https://github.com/pr1")],
    }

    assert pipeline.collected_items == expected


@pytest.mark.parametrize(
    "input_file, expected_file, repo_url, pipeline_class",
    [
        (
            "github_issues_and_pr.json",
            "expected_github.json",
            "https://github.com/test/repo",
            GitHubCollector,
        ),
        (
            "gitlab_issues_and_pr.json",
            "expected_gitlab.json",
            "https://gitlab.com/test/repo",
            GitLabCollector,
        ),
    ],
)
@pytest.mark.django_db
def test_collect_advisories_from_json(input_file, expected_file, repo_url, pipeline_class):
    input_file = TEST_DATA / input_file
    expected_file = TEST_DATA / expected_file

    issues_and_prs = json.loads(input_file.read_text(encoding="utf-8"))

    pipeline = pipeline_class()
    pipeline.pipeline_id = "collect-prs-issues"
    pipeline.repo_url = repo_url
    pipeline.log = MagicMock()

    pipeline.collect_items = MagicMock(return_value=issues_and_prs)

    result = [adv.to_dict() for adv in pipeline.collect_advisories()]
    util_tests.check_results_against_json(result, expected_file)
