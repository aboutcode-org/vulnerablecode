#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from collections.abc import Mapping
from datetime import datetime

from django.test import TestCase
from django.utils import timezone
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.models import AdvisoryToDoV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.pipelines.v2_improvers.compute_advisory_todo import ComputeToDo
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.tests.pipelines import TestLogger
from vulnerabilities.utils import canonical_value


class TestComputeToDo(TestCase):
    def setUp(self):
        self.log = TestLogger()
        self.advisory_data1 = AdvisoryDataV2(
            advisory_id="test_id",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.0"),
                )
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data2 = AdvisoryDataV2(
            advisory_id="test_id_1",
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                )
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data3 = AdvisoryDataV2(
            advisory_id="test_id_2",
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.0"),
                )
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data4 = AdvisoryDataV2(
            advisory_id="test_id_3",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<=2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.1"),
                )
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data5 = AdvisoryDataV2(
            advisory_id="test_id_5",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package2"),
                    affected_version_range=VersionRange.from_string(
                        "vers:npm/>=1.0.0|<=2.0.0|>=3.0.0|<=3.9.0"
                    ),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.1"),
                ),
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<=2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.1"),
                ),
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data6 = AdvisoryDataV2(
            advisory_id="test_id_6",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package2"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<=2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.1"),
                ),
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package2"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=3.0.0|<=3.9.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/3.9.1"),
                ),
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<=2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.1"),
                ),
                AffectedPackageV2(
                    package=PackageURL(type="pypi", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:pypi/>=1.0.0|<=2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:pypi/2.0.1"),
                ),
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data7 = AdvisoryDataV2(
            advisory_id="test_id_5",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package2"),
                    affected_version_range=VersionRange.from_string(
                        "vers:npm/>=1.0.0|<=2.0.0|>=3.0.0|<=3.9.0"
                    ),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.1"),
                ),
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.1"),
                ),
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data8 = AdvisoryDataV2(
            advisory_id="test_id_5",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package2"),
                    affected_version_range=VersionRange.from_string(
                        "vers:npm/>=1.0.0|<=2.0.0|>=3.0.0|<=3.9.0"
                    ),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.1"),
                ),
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<=1.9.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.0"),
                ),
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data9 = AdvisoryDataV2(
            advisory_id="test_id9",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.0"),
                )
            ],
            severities=[
                VulnerabilitySeverity(
                    system=severity_systems.CVSSV31,
                    scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L",
                    value="8.3",
                ),
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data11 = AdvisoryDataV2(
            advisory_id="test_id_11",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package2"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.0"),
                )
            ],
            severities=[
                VulnerabilitySeverity(
                    system=severity_systems.CVSSV31,
                    scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    value="8.8",
                ),
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data10 = AdvisoryDataV2(
            advisory_id="test_id_10",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.0"),
                )
            ],
            severities=[
                VulnerabilitySeverity(
                    system=severity_systems.CVSSV31,
                    scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    value="8.8",
                ),
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data12 = AdvisoryDataV2(
            advisory_id="test_id_12",
            aliases=["CVE-000-000"],
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                    fixed_version_range=VersionRange.from_string("vers:npm/2.0.0"),
                )
            ],
            severities=[
                VulnerabilitySeverity(
                    system=severity_systems.CVSSV3,
                    scoring_elements="CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    value="8.8",
                ),
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

    def test_advisory_todo_missing_summary(self):
        insert_advisory_v2(
            advisory=self.advisory_data1,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
            datasource_id="test1",
        )
        adv = AdvisoryV2.objects.first()
        adv.summary = ""
        cur = timezone.now()
        adv._all_impacts_unfurled_at = cur
        adv.save()
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_SUMMARY", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_missing_fixed(self):
        adv = insert_advisory_v2(
            advisory=self.advisory_data2,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
            datasource_id="test1",
        )
        pipeline = ComputeToDo()
        cur = timezone.now()
        adv._all_impacts_unfurled_at = cur
        adv.save()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_FIXED_BY_PACKAGE", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_missing_affected(self):
        adv = insert_advisory_v2(
            advisory=self.advisory_data3,
            logger=self.log.write,
            datasource_id="test1",
            pipeline_id="test_pipeline1",
        )
        cur = timezone.now()
        adv._all_impacts_unfurled_at = cur
        adv.save()
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_AFFECTED_PACKAGE", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_conflicting_fixed_affected(self):
        insert_advisory_v2(
            advisory=self.advisory_data1,
            logger=self.log.write,
            datasource_id="test1",
            pipeline_id="test_pipeline1",
        )
        insert_advisory_v2(
            advisory=self.advisory_data4,
            logger=self.log.write,
            datasource_id="test4",
            pipeline_id="test_pipeline4",
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        adv = AdvisoryV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertIn(
            "87d9e2627a8461fc5c068335d822af4aa0a40a8f265a92895c51d275d97ab0d6",
            todo.issue_detail["conflict_checksum"],
        )
        self.assertEqual(2, todo.advisories.count())
        self.assertEqual(todo, adv.advisory_todos.first())

    def test_todo_at_package_alias_intersection(self):
        insert_advisory_v2(
            advisory=self.advisory_data4,
            pipeline_id="test_pipeline4",
            logger=self.log.write,
            datasource_id="test4",
        )
        insert_advisory_v2(
            advisory=self.advisory_data5,
            pipeline_id="test_pipeline5",
            logger=self.log.write,
            datasource_id="test5",
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())

    def test_todo_conflict_details_partial_curation(self):
        expected_partial_curation_advisory = {
            "advisory_id": "PLACEHOLDER_PARTIAL_CURATION_AVID",
            "aliases": ["CVE-000-000"],
            "summary": "[test5/test_id_5, test6/test_id_6]: Test summary",
            "affected_packages": [
                {
                    "package": {
                        "type": "npm",
                        "namespace": "",
                        "name": "package2",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": "vers:npm/>=1.0.0|<=2.0.0",
                    "fixed_version_range": None,
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                },
                {
                    "package": {
                        "type": "npm",
                        "namespace": "",
                        "name": "package2",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": "vers:npm/>=3.0.0|<=3.9.0",
                    "fixed_version_range": None,
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                },
                {
                    "package": {
                        "type": "pypi",
                        "namespace": "",
                        "name": "package1",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": "vers:pypi/>=1.0.0|<=2.0.0",
                    "fixed_version_range": "vers:pypi/2.0.1",
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                },
                {
                    "package": {
                        "type": "npm",
                        "namespace": "",
                        "name": "package1",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": "vers:npm/>=1.0.0|<=2.0.0",
                    "fixed_version_range": "vers:npm/2.0.1",
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                },
            ],
            "references": [
                {"reference_id": "", "reference_type": "", "url": "https://example.com/vuln1"}
            ],
            "patches": [],
            "severities": [],
            "date_published": None,
            "weaknesses": [],
            "url": "",
        }

        insert_advisory_v2(
            advisory=self.advisory_data5,
            pipeline_id="test_pipeline5",
            logger=self.log.write,
            datasource_id="test5",
        )
        insert_advisory_v2(
            advisory=self.advisory_data6,
            pipeline_id="test_pipeline6",
            logger=self.log.write,
            datasource_id="test6",
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        issue_details = todo.issue_detail
        result_partial_curation = issue_details["partial_curation_advisory"]
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertEqual(
            normalize(expected_partial_curation_advisory),
            normalize(result_partial_curation),
        )

    def test_todo_conflict_details_partial_curation_unpaired_purl_and_conflicting_affected_and_fixed(
        self,
    ):
        expected_partial_curation_advisory = {
            "advisory_id": "PLACEHOLDER_PARTIAL_CURATION_AVID",
            "aliases": ["CVE-000-000"],
            "summary": "[test1/test_id, test5/test_id_5]: Test summary",
            "affected_packages": [
                {
                    "package": {
                        "type": "npm",
                        "namespace": "",
                        "name": "package2",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": "vers:npm/>=1.0.0|<=2.0.0|>=3.0.0|<=3.9.0",
                    "fixed_version_range": "vers:npm/2.0.1",
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                }
            ],
            "references": [
                {"reference_id": "", "reference_type": "", "url": "https://example.com/vuln1"}
            ],
            "patches": [],
            "severities": [],
            "date_published": None,
            "weaknesses": [],
            "url": "",
        }

        insert_advisory_v2(
            advisory=self.advisory_data5,
            pipeline_id="test_pipeline5",
            logger=self.log.write,
            datasource_id="test5",
        )
        insert_advisory_v2(
            advisory=self.advisory_data1,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
            datasource_id="test1",
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        issue_details = todo.issue_detail
        result_partial_curation = issue_details["partial_curation_advisory"]
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertDictEqual(expected_partial_curation_advisory, result_partial_curation)

    def test_todo_conflict_details_partial_curation_unpaired_purl_and_conflicting_fixed(self):
        expected_partial_curation_advisory = {
            "advisory_id": "PLACEHOLDER_PARTIAL_CURATION_AVID",
            "aliases": ["CVE-000-000"],
            "summary": "[test1/test_id, test7/test_id_5]: Test summary",
            "affected_packages": [
                {
                    "package": {
                        "type": "npm",
                        "namespace": "",
                        "name": "package1",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": "vers:npm/>=1.0.0|<2.0.0",
                    "fixed_version_range": None,
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                },
                {
                    "package": {
                        "type": "npm",
                        "namespace": "",
                        "name": "package2",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": "vers:npm/>=1.0.0|<=2.0.0|>=3.0.0|<=3.9.0",
                    "fixed_version_range": "vers:npm/2.0.1",
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                },
            ],
            "references": [
                {"reference_id": "", "reference_type": "", "url": "https://example.com/vuln1"}
            ],
            "patches": [],
            "severities": [],
            "date_published": None,
            "weaknesses": [],
            "url": "",
        }

        insert_advisory_v2(
            advisory=self.advisory_data1,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
            datasource_id="test1",
        )
        insert_advisory_v2(
            advisory=self.advisory_data7,
            pipeline_id="test_pipeline7",
            logger=self.log.write,
            datasource_id="test7",
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        issue_details = todo.issue_detail
        result_partial_curation = issue_details["partial_curation_advisory"]
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertEqual(
            normalize(expected_partial_curation_advisory),
            normalize(result_partial_curation),
        )

    def test_todo_conflict_details_partial_curation_unpaired_purl_and_conflicting_affected(self):
        expected_partial_curation_advisory = {
            "advisory_id": "PLACEHOLDER_PARTIAL_CURATION_AVID",
            "aliases": ["CVE-000-000"],
            "summary": "[test1/test_id, test8/test_id_5]: Test summary",
            "affected_packages": [
                {
                    "package": {
                        "type": "npm",
                        "namespace": "",
                        "name": "package1",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": None,
                    "fixed_version_range": "vers:npm/2.0.0",
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                },
                {
                    "package": {
                        "type": "npm",
                        "namespace": "",
                        "name": "package2",
                        "version": "",
                        "qualifiers": "",
                        "subpath": "",
                    },
                    "affected_version_range": "vers:npm/>=1.0.0|<=2.0.0|>=3.0.0|<=3.9.0",
                    "fixed_version_range": "vers:npm/2.0.1",
                    "introduced_by_commit_patches": [],
                    "fixed_by_commit_patches": [],
                },
            ],
            "references": [
                {"reference_id": "", "reference_type": "", "url": "https://example.com/vuln1"}
            ],
            "patches": [],
            "severities": [],
            "date_published": None,
            "weaknesses": [],
            "url": "",
        }

        insert_advisory_v2(
            advisory=self.advisory_data1,
            logger=self.log.write,
            datasource_id="test1",
            pipeline_id="test_pipeline1",
        )
        insert_advisory_v2(
            advisory=self.advisory_data8,
            logger=self.log.write,
            datasource_id="test8",
            pipeline_id="test_pipeline8",
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        issue_details = todo.issue_detail
        result_partial_curation = issue_details["partial_curation_advisory"]
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_AFFECTED_PACKAGES", todo.issue_type)
        self.assertCountEqual(
            expected_partial_curation_advisory["affected_packages"],
            result_partial_curation["affected_packages"],
        )

    def test_todo_conflicting_severity(self):
        insert_advisory_v2(
            advisory=self.advisory_data9,
            logger=self.log.write,
            datasource_id="test9",
            pipeline_id="test_pipeline9",
        )
        insert_advisory_v2(
            advisory=self.advisory_data10,
            logger=self.log.write,
            datasource_id="test10",
            pipeline_id="test_pipeline10",
        )

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        adv = AdvisoryV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_SEVERITY_SCORES", todo.issue_type)
        self.assertEqual(2, todo.advisories.count())
        self.assertEqual(todo, adv.advisory_todos.first())

    def test_todo_conflicting_severity_with_no_common_purl(self):
        insert_advisory_v2(
            advisory=self.advisory_data9,
            logger=self.log.write,
            datasource_id="test9",
            pipeline_id="test_pipeline9",
        )
        insert_advisory_v2(
            advisory=self.advisory_data11,
            logger=self.log.write,
            datasource_id="test11",
            pipeline_id="test_pipeline11",
        )

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())

    def test_todo_conflicting_severity_with_no_common_cvss(self):
        insert_advisory_v2(
            advisory=self.advisory_data10,
            logger=self.log.write,
            datasource_id="test10",
            pipeline_id="test_pipeline10",
        )
        insert_advisory_v2(
            advisory=self.advisory_data12,
            logger=self.log.write,
            datasource_id="test12",
            pipeline_id="test_pipeline12",
        )

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())


def normalize(obj):
    if isinstance(obj, Mapping):
        return {k: normalize(v) for k, v in sorted(obj.items())}

    if isinstance(obj, list):
        normalized = [normalize(item) for item in obj]

        return sorted(
            normalized,
            key=lambda x: repr(x),
        )

    return obj
