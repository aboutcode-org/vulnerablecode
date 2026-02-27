#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from datetime import timedelta

from django.test import TestCase
from fetchcode.package_versions import PackageVersion
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GemVersionRange
from univers.version_range import VersionRange
from univers.versions import RubygemsVersion

from vulnerabilities import utils
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines import insert_advisory_v2
from vulnerabilities.references import XsaReferenceV2
from vulnerabilities.references import ZbxReferenceV2
from vulnerabilities.utils import AffectedPackage
from vulnerabilities.utils import get_item
from vulnerabilities.utils import get_severity_range
from vulnerabilities.utils import nearest_patched_package
from vulnerabilities.utils import resolve_version_range
from vulnerabilities.utils import split_markdown_front_matter


def test_nearest_patched_package():

    result = nearest_patched_package(
        vulnerable_packages=[
            PackageURL(type="npm", name="foo", version="2.0.4"),
            PackageURL(type="npm", name="foo", version="2.0.0"),
            PackageURL(type="npm", name="foo", version="2.0.1"),
            PackageURL(type="npm", name="foo", version="1.9.8"),
        ],
        resolved_packages=[
            PackageURL(type="npm", name="foo", version="2.0.2"),
            PackageURL(type="npm", name="foo", version="1.9.9"),
        ],
    )

    assert [
        AffectedPackage(
            vulnerable_package=PackageURL(
                type="npm", namespace=None, name="foo", version="1.9.8", qualifiers={}, subpath=None
            ),
            patched_package=PackageURL(
                type="npm", namespace=None, name="foo", version="1.9.9", qualifiers={}, subpath=None
            ),
        ),
        AffectedPackage(
            vulnerable_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.0", qualifiers={}, subpath=None
            ),
            patched_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.2", qualifiers={}, subpath=None
            ),
        ),
        AffectedPackage(
            vulnerable_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.1", qualifiers={}, subpath=None
            ),
            patched_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.2", qualifiers={}, subpath=None
            ),
        ),
        AffectedPackage(
            vulnerable_package=PackageURL(
                type="npm", namespace=None, name="foo", version="2.0.4", qualifiers={}, subpath=None
            ),
            patched_package=None,
        ),
    ] == result


def test_split_markdown_front_matter():
    text = """---
title: DUMMY-SECURITY-2019-001
description: Incorrect access control.
cves: [CVE-2042-1337]
---
# Markdown starts here
"""

    expected = (
        """title: DUMMY-SECURITY-2019-001
description: Incorrect access control.
cves: [CVE-2042-1337]""",
        "# Markdown starts here",
    )

    results = split_markdown_front_matter(text)
    assert results == expected


def test_get_item():
    d1 = {"a": {"b": {"c": None}}}
    assert get_item(d1, "a", "b", "c", "d") == None
    d2 = {"a": {"b": {"c": {"d": None}}}}
    assert get_item(d2, "a", "b", "c", "e") == None
    d3 = ["a", "b", "c", "d"]
    assert get_item(d3, "a", "b") == None
    d4 = {"a": {"b": {"c": {"d": []}}}}
    assert get_item(d4, "a", "b", "c", "d", "e") == None
    d5 = {"a": {"b": {"c": "d"}}}
    assert get_item(d5, "a", "b", "c", "d") == None
    assert get_item(d5, "a", "b", "c") == "d"


def test_resolve_version_range():
    assert (["1.0.0", "2.0.0"], ["10.0.0"]) == resolve_version_range(
        GemVersionRange(
            constraints=(
                VersionConstraint(comparator="<", version=RubygemsVersion(string="9.0.0")),
            )
        ),
        [
            "1.0.0",
            "2.0.0",
            "10.0.0",
        ],
        [],
    )


def test_resolve_version_range_failure(caplog):
    assert ([], []) == resolve_version_range(
        None,
        [
            PackageVersion(value="1.0.0"),
            PackageVersion(value="2.0.0"),
            PackageVersion(value="10.0.0"),
        ],
        [],
    )
    assert "affected version range is" in caplog.text


def test_resolve_version_range_without_ignorable_versions():
    assert (["1.0.0", "2.0.0"], ["10.0.0"]) == resolve_version_range(
        GemVersionRange(
            constraints=(
                VersionConstraint(comparator="<", version=RubygemsVersion(string="9.0.0")),
            )
        ),
        [
            "1.0.0",
            "2.0.0",
            "10.0.0",
        ],
    )


def test_get_severity_range():
    assert get_severity_range({""}) is None
    assert get_severity_range({}) is None


class TestComputeContentIdV2(TestCase):
    def setUp(self):
        self.advisory1 = AdvisoryDataV2(
            summary="Test advisory",
            aliases=["CVE-2025-0001", "CVE-2024-0001"],
            references=[
                XsaReferenceV2.from_number(248),
                ZbxReferenceV2.from_id("ZBX-000"),
            ],
            severities=[
                VulnerabilitySeverity.from_dict(
                    {
                        "system": "cvssv4",
                        "value": "7.5",
                        "scoring_elements": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    }
                ),
                VulnerabilitySeverity.from_dict(
                    {
                        "system": "cvssv3",
                        "value": "6.5",
                        "scoring_elements": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    }
                ),
            ],
            weaknesses=[296, 233],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=VersionRange.from_string("vers:npm/<=1.2.3"),
                    fixed_version_range=VersionRange.from_string("vers:npm/1.2.4"),
                    introduced_by_commit_patches=[],
                    fixed_by_commit_patches=[],
                ),
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=VersionRange.from_string("vers:npm/<=0.2.3"),
                    fixed_version_range=VersionRange.from_string("vers:npm/0.2.4"),
                    introduced_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://foobar.vcs/",
                            commit_hash="662f801f",
                        ),
                        PackageCommitPatchData(
                            vcs_url="https://foobar.vcs/",
                            commit_hash="001f801f",
                        ),
                    ],
                    fixed_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://foobar.vcs/",
                            commit_hash="982f801f",
                        ),
                        PackageCommitPatchData(
                            vcs_url="https://foobar.vcs/",
                            commit_hash="081f801f",
                        ),
                    ],
                ),
            ],
            patches=[
                PatchData(patch_url="https://foo.bar/", patch_text="test patch"),
                PatchData(patch_url="https://yet-another-foo.bar/", patch_text="some test patch"),
            ],
            advisory_id="ADV-001",
            date_published=datetime.now() - timedelta(days=10),
            url="https://example.com/advisory/1",
        )
        insert_advisory_v2(
            advisory=self.advisory1,
            pipeline_id="test_pipeline_v2",
        )

    def test_compute_content_id_v2(self):
        result = utils.compute_content_id_v2(self.advisory1)
        self.assertEqual(result, "5211f1e6c3d935759fb288d79a865eeacc06e3e0e352ab7f5b4cb0e76a43a955")

    def test_content_id_from_adv_data_and_adv_model_are_same(self):
        id_from_data = utils.compute_content_id_v2(self.advisory1)
        advisory_model = AdvisoryV2.objects.first()
        id_from_model = utils.compute_content_id_v2(advisory_model)

        self.assertEqual(id_from_data, id_from_model)
