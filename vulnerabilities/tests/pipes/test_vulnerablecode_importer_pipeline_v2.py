#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timedelta
from unittest.mock import patch

import pytest
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.models import PackageV2
from vulnerabilities.models import Patch
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.advisory import classify_patch_source


class DummyImporter(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "dummy"
    log_messages = []

    def log(self, message, level=logging.INFO):
        self.log_messages.append((level, message))

    def collect_advisories(self):
        yield from self._advisories

    def advisories_count(self):
        return len(self._advisories)


@pytest.fixture
def dummy_advisory():
    return AdvisoryData(
        summary="Test advisory",
        aliases=["CVE-2025-0001"],
        references_v2=[],
        severities=[],
        weaknesses=[],
        affected_packages=[
            AffectedPackageV2(
                package=PackageURL.from_string("pkg:npm/foobar"),
                affected_version_range=VersionRange.from_string("vers:npm/<=1.2.3"),
                fixed_version_range=VersionRange.from_string("vers:npm/1.2.4"),
                introduced_by_commit_patches=[
                    PackageCommitPatchData(
                        commit_hash="9ff29db8ec3adefefce0d37c3c9b5b2c22e59fac",
                        vcs_url="https://github.com/abc/def",
                    )
                ],
                fixed_by_commit_patches=[
                    PackageCommitPatchData(
                        commit_hash="ab99939678dc36b3bee0f366493df1aeef521df4",
                        vcs_url="https://github.com/abc/def",
                    )
                ],
            ),
            AffectedPackageV2(
                package=PackageURL.from_string("pkg:npm/foobar"),
                affected_version_range=VersionRange.from_string("vers:npm/<=3.2.3"),
                fixed_version_range=VersionRange.from_string("vers:npm/3.2.4"),
                introduced_by_commit_patches=[
                    PackageCommitPatchData(
                        commit_hash="9ff29db8ec3adefefce0d37c3c9b5b2c22e59fac",
                        vcs_url="https://github.com/abc/def",
                    )
                ],
                fixed_by_commit_patches=[
                    PackageCommitPatchData(
                        commit_hash="ab99939678dc36b3bee0f366493df1aeef521df4",
                        vcs_url="https://github.com/abc/def",
                    )
                ],
            ),
        ],
        patches=[
            PatchData(
                patch_text="patch_text",
                patch_url="example.com/1.patch",
            )
        ],
        advisory_id="ADV-123",
        date_published=datetime.now() - timedelta(days=10),
        url="https://example.com/advisory/1",
    )


@pytest.fixture
def dummy_importer(dummy_advisory):
    importer = DummyImporter()
    importer._advisories = [dummy_advisory]
    return importer


@pytest.mark.django_db
def test_collect_and_store_advisories(dummy_importer):
    dummy_importer.collect_and_store_advisories()
    assert len(dummy_importer.log_messages) >= 2
    assert "Successfully collected" in dummy_importer.log_messages[-1][1]
    assert AdvisoryV2.objects.count() == 1


@pytest.mark.django_db
@patch("vulnerabilities.pipes.advisory.get_exact_purls_v2", side_effect=Exception("error"))
def test_advisory_import_atomicity_no_partial_adv_import(mock_exception, dummy_importer):
    dummy_importer.collect_and_store_advisories()
    assert AdvisoryV2.objects.count() == 0
    assert ImpactedPackage.objects.count() == 0


@pytest.mark.django_db
def test_advisory_import_atomicity(dummy_importer):
    dummy_importer.collect_and_store_advisories()
    assert AdvisoryV2.objects.count() == 1
    assert ImpactedPackage.objects.count() == 2
    assert PackageCommitPatch.objects.count() == 2
    assert PackageV2.objects.count() == 4


@pytest.fixture
def patch_source_samples():
    return [
        {"url": "https://github.com/abc/def", "commit_hash": None, "patch_text": None},  # PatchData
        {
            "url": "https://github.com/abc/def",
            "commit_hash": None,
            "patch_text": "+1-2",
        },  # PatchData
        {
            "url": "https://github.com/abc/def",
            "commit_hash": "be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "patch_text": None,
        },  # PackageCommitPatchData
        {
            "url": "https://github.com/abc/def",
            "commit_hash": "be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "patch_text": "+1-2",
        },  # PackageCommitPatchData
        {
            "url": "https://github.com/abc/def/commit/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "commit_hash": None,
            "patch_text": None,
        },  # PackageCommitPatchData
        {
            "url": "https://github.com/abc/def/commit/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "commit_hash": None,
            "patch_text": "+1-2",
        },  # PackageCommitPatchData
        {
            "url": "https://github.com/abc/def/commit/a2a5b42fb829b4a873c832b805680fc19199a07e",
            "commit_hash": "a2a5b42fb829b4a873c832b805680fc19199a07e",
            "patch_text": None,
        },  # PackageCommitPatchData
        {
            "url": "https://github.com/abc/def/commit/a2a5b42fb829b4a873c832b805680fc19199a07e",
            "commit_hash": "a2a5b42fb829b4a873c832b805680fc19199a07e",
            "patch_text": "+1-2",
        },  # PackageCommitPatchData
        {
            "url": "https://unknown.com/abc/def",
            "commit_hash": None,
            "patch_text": None,
        },  # PatchData
        {
            "url": "https://unknown.com/abc/def",
            "commit_hash": None,
            "patch_text": "+1-2",
        },  # PatchData
        {
            "url": "https://unknown.com/abc/def",
            "commit_hash": "8eb1b04ca4ae6fc0a0ef46f1b0c042f64db28ff9",
            "patch_text": None,
        },  # ReferenceV2
        {
            "url": "https://unknown.com/abc/def",
            "commit_hash": "8eb1b04ca4ae6fc0a0ef46f1b0c042f64db28ff9",
            "patch_text": "+1-2",
        },  # ReferenceV2
        {
            "url": "https://unknown.com/abc/def/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "commit_hash": None,
            "patch_text": None,
        },  # PatchData
        {
            "url": "https://unknown.com/abc/def/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "commit_hash": None,
            "patch_text": "+1-2",
        },  # PatchData
        {
            "url": "https://unknown.com/abc/def/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "commit_hash": "be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "patch_text": None,
        },  # ReferenceV2
        {
            "url": "https://unknown.com/abc/def/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "commit_hash": "be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "patch_text": "+1-2",
        },  # ReferenceV2
    ]


@pytest.fixture
def dumpy_patch_advisory(patch_source_samples):
    references = []
    patches = []
    affected_packages = []
    for entry in patch_source_samples:
        url = entry["url"]
        commit_hash = entry["commit_hash"]
        patch_text = entry["patch_text"]

        base_purl, patch_obj = classify_patch_source(
            url=url, commit_hash=commit_hash, patch_text=patch_text
        )

        if isinstance(patch_obj, PackageCommitPatchData):
            # For testing only: commit hashes starting with "a" are treated as introduced_by_commit_patches,
            # all others are treated as fixed_by_commit_patches.
            if patch_obj.commit_hash.startswith("a"):
                affected_package = AffectedPackageV2(
                    package=base_purl,
                    introduced_by_commit_patches=[patch_obj],
                )
            else:
                affected_package = AffectedPackageV2(
                    package=base_purl,
                    fixed_by_commit_patches=[patch_obj],
                )
            affected_packages.append(affected_package)
        elif isinstance(patch_obj, PatchData):
            patches.append(patch_obj)
        elif isinstance(patch_obj, ReferenceV2):
            references.append(patch_obj)

    return AdvisoryData(
        summary="Test patch advisory",
        aliases=["CVE-2025-0001"],
        affected_packages=affected_packages,
        references_v2=references,
        patches=patches,
        advisory_id="ADV-1234",
        date_published=datetime.now() - timedelta(days=10),
        url="https://example.com/advisory/1",
    )


@pytest.mark.django_db
def test_patch_advisory(dumpy_patch_advisory):
    dumpy_patch_importer = DummyImporter()
    dumpy_patch_importer._advisories = [dumpy_patch_advisory]
    dumpy_patch_importer.collect_and_store_advisories()
    assert AdvisoryV2.objects.count() == 1
    adv = AdvisoryV2.objects.get(advisory_id="ADV-1234")

    assert ImpactedPackage.objects.count() == 6
    assert [
        (
            package_commit_patch.commit_hash,
            package_commit_patch.vcs_url,
            package_commit_patch.patch_text,
            package_commit_patch.patch_checksum,
        )
        for package_commit_patch in PackageCommitPatch.objects.all()
    ] == [
        (
            "be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "https://github.com/abc/def",
            "+1-2",
            "a5d6b89c35224d4ed69910a18fb544ca3fb26f62db53bc2769ce8a8d5cf8874c191186d170cb6e8896b0aaa8eaed891e7e819c4c0c7af499397c84761d6fb22d",
        ),
        (
            "a2a5b42fb829b4a873c832b805680fc19199a07e",
            "https://github.com/abc/def",
            "+1-2",
            "a5d6b89c35224d4ed69910a18fb544ca3fb26f62db53bc2769ce8a8d5cf8874c191186d170cb6e8896b0aaa8eaed891e7e819c4c0c7af499397c84761d6fb22d",
        ),
    ]
    assert (
        PackageCommitPatch.objects.count() == 2
    )  # Only 2 are created because the 6 inputs include duplicates with the VCS URL and commit_hash
    assert Patch.objects.count() == 6
    assert [
        (patch.patch_text, patch.patch_url, patch.patch_checksum) for patch in adv.patches.all()
    ] == [
        (None, "https://github.com/abc/def", None),
        (
            "+1-2",
            "https://github.com/abc/def",
            "a5d6b89c35224d4ed69910a18fb544ca3fb26f62db53bc2769ce8a8d5cf8874c191186d170cb6e8896b0aaa8eaed891e7e819c4c0c7af499397c84761d6fb22d",
        ),
        (None, "https://unknown.com/abc/def", None),
        (
            "+1-2",
            "https://unknown.com/abc/def",
            "a5d6b89c35224d4ed69910a18fb544ca3fb26f62db53bc2769ce8a8d5cf8874c191186d170cb6e8896b0aaa8eaed891e7e819c4c0c7af499397c84761d6fb22d",
        ),
        (None, "https://unknown.com/abc/def/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d", None),
        (
            "+1-2",
            "https://unknown.com/abc/def/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "a5d6b89c35224d4ed69910a18fb544ca3fb26f62db53bc2769ce8a8d5cf8874c191186d170cb6e8896b0aaa8eaed891e7e819c4c0c7af499397c84761d6fb22d",
        ),
    ]

    assert (
        AdvisoryReference.objects.count() == 2
    )  # Only 2 are created because the 6 inputs include duplicates with the same URL and reference ID.
    assert [(ref.url, ref.reference_type, ref.reference_id) for ref in adv.references.all()] == [
        ("https://unknown.com/abc/def", "commit", "8eb1b04ca4ae6fc0a0ef46f1b0c042f64db28ff9"),
        (
            "https://unknown.com/abc/def/be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
            "commit",
            "be891173be2fbdc897116bf5aa4fc9fdc8dc4f3d",
        ),
    ]
