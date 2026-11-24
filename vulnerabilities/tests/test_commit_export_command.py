#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from vulnerabilities.management.commands.commit_export import Command


@pytest.mark.parametrize(
    "repo_url, expected_api_url",
    [
        (
            "https://github.com/aboutcode-org/vulnerablecode-data",
            "https://api.github.com/repos/aboutcode-org/vulnerablecode-data/pulls",
        ),
        (
            "https://github.com/aboutcode-org/vulnerablecode-data.git",
            "https://api.github.com/repos/aboutcode-org/vulnerablecode-data/pulls",
        ),
        (
            "https://github.com/aboutcode-org/vulnerablecode-data/",
            "https://api.github.com/repos/aboutcode-org/vulnerablecode-data/pulls",
        ),
        # Repository names ending with any of the ".git" characters must not be truncated.
        (
            "https://github.com/aboutcode-org/vcio-export",
            "https://api.github.com/repos/aboutcode-org/vcio-export/pulls",
        ),
        (
            "https://github.com/aboutcode-org/digit.git",
            "https://api.github.com/repos/aboutcode-org/digit/pulls",
        ),
        (
            "https://github.com/aboutcode-org/test.git/",
            "https://api.github.com/repos/aboutcode-org/test/pulls",
        ),
    ],
)
@patch("vulnerabilities.management.commands.commit_export.requests.post")
def test_create_pull_request_uses_correct_repository(mock_post, repo_url, expected_api_url):
    mock_post.return_value = MagicMock(
        status_code=201, json=lambda: {"html_url": "https://example.com/pr/1"}
    )

    Command().create_pull_request(
        repo_url=repo_url,
        branch="export-update",
        title="title",
        body="body",
        token="token",
    )

    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == expected_api_url


def test_create_pull_request_rejects_url_without_owner_and_repo():
    with pytest.raises(ValueError):
        Command().create_pull_request(
            repo_url="https://github.com/aboutcode-org",
            branch="export-update",
            title="title",
            body="body",
            token="token",
        )
