#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.importer import Importer
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import PatchData
from vulnerabilities.pipes.advisory import classify_patch_source


def test_all_importers_have_unique_name():
    importers = [importer.importer_name for importer in Importer.__subclasses__()]
    empty_importers = [
        importer.__name__ for importer in Importer.__subclasses__() if not importer.importer_name
    ]
    assert empty_importers == []
    assert len(importers) == len(set(importers))


@pytest.mark.parametrize(
    "vcs_url, commit_hash, patch_text, patch_url, expected_result_tuple",
    [
        # SUPPORTED: VCS URL + commit hash + no code patch
        (
            "https://github.com/user/repo",
            "a1b2c3d4",
            None,
            None,
            (
                "pkg:github/user/repo",
                PackageCommitPatchData(
                    vcs_url="https://github.com/user/repo",
                    commit_hash="a1b2c3d4",
                    patch_text=None,
                ),
            ),
        ),
        # UNSUPPORTED: VCS URL + commit hash + no code patch
        (
            "https://unsupported.example.com/repo",
            "112233",
            None,
            None,
            (
                None,
                PatchData(
                    patch_text=None,
                    patch_url="https://unsupported.example.com/repo",
                ),
            ),
        ),
        # SUPPORTED: VCS URL + commit hash + code patch
        (
            "https://github.com/user/repo",
            "deadbeef",
            "diff --git a/file b/file",
            "https://github.com/user/repo/commit/a1b2c3d4",
            (
                "pkg:github/user/repo",
                PackageCommitPatchData(
                    commit_hash="deadbeef",
                    vcs_url="https://github.com/user/repo",
                    patch_text="diff --git a/file b/file",
                ),
            ),
        ),
        # UNSUPPORTED: VCS URL + commit hash + code patch
        (
            "https://example.com/user/unknown",
            "a1b2c3d4",
            "diff content",
            "https://example.com/user/unknown/commits/a1b2c3d4",
            (
                None,
                PatchData(
                    patch_text="diff content",
                    patch_url="https://example.com/user/unknown/commits/a1b2c3d4",
                ),
            ),
        ),
        #  NO VCS URL + NO commit hash + code patch
        (
            None,
            None,
            "diff content",
            "https://example.com/user/unknown/commits/a1b2c3d4",
            (
                None,
                PatchData(
                    patch_text="diff content",
                    patch_url="https://example.com/user/unknown/commits/a1b2c3d4",
                ),
            ),
        ),
        # SUPPORTED: VCS URL + NO commit hash + no code patch #invalid
        (
            "https://github.com/user/repo",
            None,
            None,
            None,
            (
                None,
                PatchData(
                    patch_text=None,
                    patch_url="https://github.com/user/repo",
                ),
            ),
        ),
        # UNSUPPORTED: VCS URL + NO commit hash + no code patch #invalid
        (
            "https://example.com/user/repo",
            None,
            None,
            None,
            (
                None,
                PatchData(
                    patch_text=None,
                    patch_url="https://example.com/user/repo",
                ),
            ),
        ),
        # SUPPORTED: VCS URL + NO commit hash + code patch
        (
            "https://github.com/user/repo",
            None,
            None,
            "https://github.com/user/unknown/commit/98e516011d6e096e25247b82fc5f196bbeecff10",
            (
                "pkg:github/user/unknown",
                PackageCommitPatchData(
                    vcs_url="https://github.com/user/repo",
                    commit_hash="98e516011d6e096e25247b82fc5f196bbeecff10",
                    patch_text=None,
                ),
            ),
        ),
        # UNSUPPORTED: VCS URL + NO commit hash + code patch
        (
            "https://example.com/user/repo",
            None,
            None,
            "https://example.com/user/unknown/commits/98e516011d6e096e25247b82fc5f196bbeecff10.patch",
            (
                None,
                PatchData(
                    patch_text=None,
                    patch_url="https://example.com/user/unknown/commits/98e516011d6e096e25247b82fc5f196bbeecff10.patch",
                ),
            ),
        ),
    ],
)
def test_classify_patch_source_integration(
    vcs_url, commit_hash, patch_text, patch_url, expected_result_tuple
):
    expected_purl, expected_data_obj = expected_result_tuple

    actual_purl, actual_data_obj = classify_patch_source(
        vcs_url=vcs_url, commit_hash=commit_hash, patch_text=patch_text, patch_url=patch_url
    )

    assert isinstance(actual_data_obj, type(expected_data_obj))

    if isinstance(actual_data_obj, PackageCommitPatchData):
        assert actual_data_obj.vcs_url == expected_data_obj.vcs_url
        assert actual_data_obj.commit_hash == expected_data_obj.commit_hash
        assert actual_data_obj.patch_text == expected_data_obj.patch_text
        assert str(actual_purl) == expected_purl

    elif isinstance(actual_data_obj, PatchData):
        assert actual_data_obj.patch_url == expected_data_obj.patch_url
        assert actual_data_obj.patch_text == expected_data_obj.patch_text
        assert actual_purl is None
