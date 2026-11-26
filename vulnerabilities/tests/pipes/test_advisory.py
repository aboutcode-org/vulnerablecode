#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import AdvisoryWeakness
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.pipes.advisory import get_or_create_advisory_aliases
from vulnerabilities.pipes.advisory import get_or_create_advisory_package_commit_patches
from vulnerabilities.pipes.advisory import get_or_create_advisory_references
from vulnerabilities.pipes.advisory import get_or_create_advisory_severities
from vulnerabilities.pipes.advisory import get_or_create_advisory_weaknesses
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.tests.pipelines import TestLogger
from vulnerabilities.utils import compute_content_id_v2


class TestPipeAdvisory(TestCase):
    def setUp(self):
        self.logger = TestLogger()
        self.advisory_data1 = AdvisoryDataV2(
            advisory_id="CVE-2020-13371337",
            summary="vulnerability description here",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="pypi", name="dummy"),
                    affected_version_range=VersionRange.from_string("vers:pypi/>=1.0.0|<=2.0.0"),
                )
            ],
            references=[ReferenceV2(url="https://example.com/with/more/info/CVE-2020-13371337")],
            date_published=timezone.now(),
            url="https://test.com",
        )

    def test_vulnerability_pipes_get_or_create_aliases(self):
        aliases = ["CVE-TEST-123", "CVE-TEST-124"]
        result_aliases = get_or_create_advisory_aliases(aliases=aliases)
        result_alias_values = [i.alias for i in result_aliases]
        assert 2 == len(result_aliases)
        assert "CVE-TEST-123" in result_alias_values
        assert "CVE-TEST-124" in result_alias_values

    def test_advisory_insert_without_url(self):
        with self.assertRaises(ValidationError):
            AdvisoryV2(
                advisory_id=self.advisory_data1.advisory_id,
                avid=f"test/{self.advisory_data1.advisory_id}",
                datasource_id="test",
                pipeline_id="test_pipeline_v2",
                unique_content_id=compute_content_id_v2(self.advisory_data1),
                summary=self.advisory_data1.summary,
            ).full_clean()

    def test_advisory_insert_without_content_id(self):
        with self.assertRaises(ValidationError):
            AdvisoryV2(
                advisory_id=self.advisory_data1.advisory_id,
                avid=f"test/{self.advisory_data1.advisory_id}",
                datasource_id="test",
                pipeline_id="test_pipeline_v2",
                url=self.advisory_data1.url,
                summary=self.advisory_data1.summary,
            ).full_clean()

    def test_advisory_insert_no_duplicate_content_id(self):
        insert_advisory_v2(
            advisory=self.advisory_data1,
            pipeline_id="test_pipeline_v2",
            datasource_id="test",
            logger=self.logger.write,
        )

        with self.assertRaises(ValidationError):
            AdvisoryV2(
                advisory_id="CVE-OTHER",
                avid="test/CVE-OTHER",
                datasource_id="test",
                pipeline_id="test_pipeline_v2",
                unique_content_id=compute_content_id_v2(self.advisory_data1),
                url="https://other.example.com",
                summary=self.advisory_data1.summary,
            ).full_clean()


@pytest.fixture
def advisory_aliases():
    return ["CVE-2021-12345", "GHSA-xyz"]


@pytest.fixture
def advisory_references():
    return [
        ReferenceV2(reference_id="REF-1", url="https://example.com/advisory/1"),
        ReferenceV2(reference_id="REF-2", url="https://example.com/advisory/2"),
        ReferenceV2(reference_id="", url="https://example.com/advisory/3"),
        ReferenceV2(url="https://example.com/advisory/4"),
    ]


@pytest.fixture
def advisory_commit():
    return [
        PackageCommitPatchData(
            commit_hash="ef1659c01708b2111d6f06e2aa32f0f9d8768e10",
            vcs_url="https://github.com/aboutcode-org/vulnerablecode",
            patch_text="""
            @@ -2,3 +2,3 @@
            -old line
            +new line
            """,
        ),
        PackageCommitPatchData(
            commit_hash="eccbb45ac2d9c0eb7e22ea82d1fc49f9f4cda818",
            vcs_url="https://github.com/aboutcode-org/vulnerablecode",
        ),
    ]


@pytest.fixture
def advisory_severities():
    class Severity:
        def __init__(self, system, value, scoring_elements, published_at=None, url=None):
            self.system = system
            self.value = value
            self.scoring_elements = scoring_elements
            self.published_at = published_at
            self.url = url

    class System:
        def __init__(self, identifier):
            self.identifier = identifier

    return [
        Severity(
            System("CVSSv3"),
            "7.5",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            timezone.now(),
            "https://cvss.example.com",
        ),
    ]


@pytest.fixture
def advisory_weaknesses():
    return [79, 89]


@pytest.mark.django_db
def test_get_or_create_advisory_aliases(advisory_aliases):
    aliases = get_or_create_advisory_aliases(advisory_aliases)
    assert len(aliases) == len(advisory_aliases)
    for alias_obj in aliases:
        assert isinstance(alias_obj, AdvisoryAlias)
        assert alias_obj.alias in advisory_aliases


@pytest.mark.django_db
def test_get_or_create_advisory_references(advisory_references):
    refs = get_or_create_advisory_references(advisory_references)
    assert len(refs) == len(advisory_references)
    for ref in refs:
        assert isinstance(ref, AdvisoryReference)
        assert ref.url in [r.url for r in advisory_references]


@pytest.mark.django_db
def test_get_or_create_advisory_severities(advisory_severities):
    sevs = get_or_create_advisory_severities(advisory_severities)
    assert len(sevs) == len(advisory_severities)
    for sev in sevs:
        assert isinstance(sev, AdvisorySeverity)
        assert sev.scoring_system == advisory_severities[0].system.identifier
        assert sev.value == advisory_severities[0].value


@pytest.mark.django_db
def test_get_or_create_advisory_weaknesses(advisory_weaknesses):
    weaknesses = get_or_create_advisory_weaknesses(advisory_weaknesses)
    assert len(weaknesses) == len(advisory_weaknesses)
    for w in weaknesses:
        assert isinstance(w, AdvisoryWeakness)
        assert w.cwe_id in advisory_weaknesses


@pytest.mark.django_db
def test_get_or_create_advisory_commit(advisory_commit):
    commits = get_or_create_advisory_package_commit_patches(advisory_commit)
    assert len(commits) == len(advisory_commit)
    for commit in commits:
        assert isinstance(commit, PackageCommitPatch)
        assert commit.commit_hash in [c.commit_hash for c in advisory_commit]
        assert commit.vcs_url in [c.vcs_url for c in advisory_commit]


class TestLatestAdvisoryV2(TestCase):
    def setUp(self):
        self.logger = TestLogger()
        self.advisory1 = AdvisoryDataV2(
            summary="Test advisory old",
            aliases=["CVE-2025-0001"],
            references=[],
            severities=[],
            weaknesses=[],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=VersionRange.from_string("vers:npm/>3.2.1|<4.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/4.0.0"),
                    introduced_by_commit_patches=[],
                    fixed_by_commit_patches=[],
                ),
            ],
            patches=[],
            advisory_id="GHSA-1234",
            url="https://example.com/advisory",
        )

        self.advisory2 = AdvisoryDataV2(
            summary="Test advisory new",
            aliases=["CVE-2025-0001"],
            references=[],
            severities=[],
            weaknesses=[],
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=VersionRange.from_string("vers:npm/>3.2.1|<4.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/4.0.0"),
                    introduced_by_commit_patches=[],
                    fixed_by_commit_patches=[],
                ),
                AffectedPackageV2(
                    package=PackageURL.from_string("pkg:npm/foobar"),
                    affected_version_range=None,
                    fixed_version_range=None,
                    introduced_by_commit_patches=[],
                    fixed_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="https://foobar.vcs/",
                            commit_hash="982f801f",
                        ),
                    ],
                ),
            ],
            patches=[],
            advisory_id="GHSA-1234",
            url="https://example.com/advisory",
        )

        insert_advisory_v2(
            advisory=self.advisory1,
            pipeline_id="test_pipeline_v2",
            logger=self.logger.write,
            datasource_id="test",
        )

    def test_latest_advisory_update_on_advisory_insert(self):
        adv_old = AdvisoryV2.objects.get(avid="test/GHSA-1234", is_latest=True)
        insert_advisory_v2(
            advisory=self.advisory2,
            pipeline_id="test_pipeline_v2",
            logger=self.logger.write,
            datasource_id="test",
        )
        adv_new = AdvisoryV2.objects.get(avid="test/GHSA-1234", is_latest=True)
        self.assertEqual("Test advisory old", adv_old.summary)
        self.assertEqual("Test advisory new", adv_new.summary)
