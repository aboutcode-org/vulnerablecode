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
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipes.advisory import classify_patch_source


def test_all_importers_have_unique_name():
    importers = [importer.importer_name for importer in Importer.__subclasses__()]
    empty_importers = [
        importer.__name__ for importer in Importer.__subclasses__() if not importer.importer_name
    ]
    assert empty_importers == []
    assert len(importers) == len(set(importers))


@pytest.mark.parametrize(
    "url, commit_hash, patch_text, results",
    [
        # SUPPORTED: VCS URL + commit hash + no code patch
        (
            "https://github.com/user/repo",
            "a5f3206663e16c0686739fa83fca2978e6818b6",
            None,
            (
                "pkg:github/user/repo",
                [
                    PackageCommitPatchData(
                        vcs_url="https://github.com/user/repo",
                        commit_hash="a5f3206663e16c0686739fa83fca2978e6818b6",
                        patch_text=None,
                    )
                ],
            ),
        ),
        # UNSUPPORTED: VCS URL + commit hash + no code patch
        (
            "https://unsupported.example.com/repo",
            "a5f3206663e16c0686739fa83fca2978e6818b6",
            None,
            (
                None,
                [
                    ReferenceV2(
                        reference_id="a5f3206663e16c0686739fa83fca2978e6818b6",
                        reference_type="commit",
                        url="https://unsupported.example.com/repo",
                    )
                ],
            ),
        ),
        # SUPPORTED: VCS URL + commit hash + code patch
        (
            "https://github.com/user/repo/commit/a1b2c3d4",
            "a1b2c3d4",
            "diff --git a/file b/file",
            (
                "pkg:github/user/repo",
                [
                    PackageCommitPatchData(
                        commit_hash="a1b2c3d4",
                        vcs_url="https://github.com/user/repo",
                        patch_text="diff --git a/file b/file",
                    )
                ],
            ),
        ),
        # UNSUPPORTED: VCS URL + commit hash + code patch
        (
            "https://example.com/user/unknown/commits/a1b2c3d4",
            "a1b2c3d4",
            "diff content",
            (
                None,
                [
                    ReferenceV2(
                        reference_id="a1b2c3d4",
                        reference_type="commit",
                        url="https://example.com/user/unknown/commits/a1b2c3d4",
                    ),
                    PatchData(
                        patch_url="https://example.com/user/unknown/commits/a1b2c3d4",
                        patch_text="diff content",
                    ),
                ],
            ),
        ),
        #  NO VCS URL + NO commit hash + code patch
        (
            "https://example.com/user/unknown/commits/a1b2c3d4",
            None,
            "diff content",
            (
                None,
                [
                    PatchData(
                        patch_text="diff content",
                        patch_url="https://example.com/user/unknown/commits/a1b2c3d4",
                    )
                ],
            ),
        ),
        # SUPPORTED: VCS URL + NO commit hash + no code patch #invalid
        (
            "https://github.com/user/repo",
            None,
            None,
            (
                None,
                [
                    PatchData(
                        patch_text=None,
                        patch_url="https://github.com/user/repo",
                    )
                ],
            ),
        ),
        # UNSUPPORTED: VCS URL + NO commit hash + no code patch #invalid
        (
            "https://example.com/user/repo",
            None,
            None,
            (
                None,
                [
                    PatchData(
                        patch_text=None,
                        patch_url="https://example.com/user/repo",
                    )
                ],
            ),
        ),
        # SUPPORTED: VCS URL + NO commit hash + code patch
        (
            "https://github.com/user/unknown/commit/98e516011d6e096e25247b82fc5f196bbeecff10",
            None,
            None,
            (
                "pkg:github/user/unknown",
                [
                    PackageCommitPatchData(
                        vcs_url="https://github.com/user/unknown",
                        commit_hash="98e516011d6e096e25247b82fc5f196bbeecff10",
                        patch_text=None,
                    )
                ],
            ),
        ),
        # UNSUPPORTED: VCS URL + NO commit hash + code patch
        (
            "https://example.com/user/unknown/commits/98e516011d6e096e25247b82fc5f196bbeecff10.patch",
            None,
            "diff content",
            (
                None,
                [
                    PatchData(
                        patch_text="diff content",
                        patch_url="https://example.com/user/unknown/commits/98e516011d6e096e25247b82fc5f196bbeecff10.patch",
                    )
                ],
            ),
        ),
    ],
)
def test_classify_patch_source_integration(url, commit_hash, patch_text, results):
    expected_purl, expected_data_objs = results

    actual_purl, actual_data_objs = classify_patch_source(
        url=url, commit_hash=commit_hash, patch_text=patch_text
    )

    if expected_purl:
        assert str(actual_purl) == expected_purl
    else:
        assert actual_purl is None

    for actual_data_obj, expected_data_obj in zip(actual_data_objs, expected_data_objs):
        assert type(actual_data_obj) is type(expected_data_obj)
        if isinstance(actual_data_obj, PackageCommitPatchData):
            assert actual_data_obj.vcs_url == expected_data_obj.vcs_url
            assert actual_data_obj.commit_hash == expected_data_obj.commit_hash
            assert actual_data_obj.patch_text == expected_data_obj.patch_text

        elif isinstance(actual_data_obj, PatchData):
            assert actual_data_obj.patch_url == expected_data_obj.patch_url
            assert actual_data_obj.patch_text == expected_data_obj.patch_text

        elif isinstance(actual_data_obj, ReferenceV2):
            assert actual_data_obj.reference_id == expected_data_obj.reference_id
            assert actual_data_obj.reference_type == expected_data_obj.reference_type
            assert actual_data_obj.url == expected_data_obj.url
