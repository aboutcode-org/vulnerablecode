#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest import mock
from unittest.mock import MagicMock

import pytest

from vulnerabilities.models import PackageCommitPatch, Patch
from vulnerabilities.pipelines.v2_improvers.fetch_patch_url import FetchPatchURLImproverPipeline


@pytest.mark.django_db
@mock.patch("vulnerabilities.utils.requests.get")
def test_collect_patch_text_success(mock_get):
    res1 = MagicMock(status_code=200, text="diff --git a/file1")
    res2 = MagicMock(status_code=200, text="diff --git a/file2")
    mock_get.side_effect = [res1, res2]

    pcp = PackageCommitPatch.objects.create(
        vcs_url="https://github.com/nexB/vulnerablecode",
        commit_hash="abc1234",
        patch_text=None
    )

    patch = Patch.objects.create(
        patch_url="https://gitlab.com/nexB/vulnerablecode/-/commit/def5678.patch",
        patch_text=None
    )
    pipeline = FetchPatchURLImproverPipeline()
    pipeline.collect_patch_text()

    pcp.refresh_from_db()
    patch.refresh_from_db()

    assert pcp.patch_text == "diff --git a/file1"
    assert patch.patch_text == "diff --git a/file2"

@pytest.mark.django_db
@mock.patch("vulnerabilities.utils.requests.get")
def test_collect_patch_text_failure(mock_get):
    mock_get.side_effect = Exception("Connection Error")

    pcp = PackageCommitPatch.objects.create(
        vcs_url="https://github.com/nexB/vulnerablecode",
        commit_hash="abc1234",
        patch_text=None
    )

    pipeline = FetchPatchURLImproverPipeline()
    pipeline.collect_patch_text()
    assert pcp.patch_text is None