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
from pathlib import Path
from unittest.mock import patch

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
from vulnerabilities.models import ToDoRelatedAdvisoryV2
from vulnerabilities.pipelines.v2_improvers.compute_advisory_todo import ComputeToDo
from vulnerabilities.pipes.advisory import advisories_checksum
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.tests.pipelines import TestLogger
from vulnerabilities.utils import canonical_value
from vulnerabilities.utils import load_json


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


class TestInconsistentPackageVersions(TestCase):
    def setUp(self):
        fixture = Path(__file__).parents[2] / "test_data/compute_advisory_todo/npm-92.json"
        self.advisory_data = AdvisoryDataV2.from_dict(load_json(fixture))
        self.log = TestLogger()

    def insert_advisory(self):
        return insert_advisory_v2(
            advisory=self.advisory_data,
            pipeline_id="test_pipeline",
            datasource_id="test_npm",
            logger=self.log.write,
        )

    def test_creates_todo_for_affected_and_fixed_version_in_one_advisory(self):
        advisory = self.insert_advisory()
        impact = advisory.impacted_packages.get()
        self.assertTrue(impact.affecting_packages.filter(version="3.0.0").exists())
        self.assertTrue(impact.fixed_by_packages.filter(version="3.0.0").exists())
        self.assertFalse(advisory.aliases.exists())

        ComputeToDo().execute()

        todo = AdvisoryToDoV2.objects.get()
        self.assertEqual("CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertEqual([advisory], list(todo.advisories.all()))
        self.assertEqual(1, todo.advisories_count)
        self.assertEqual("92", todo.alias)
        self.assertEqual(advisory.date_published, todo.oldest_advisory_date)
        details = todo.issue_detail["conflict_details"]
        self.assertEqual(["3.0.0"], details[impact.base_purl]["conflicting_versions"])
        (item,) = todo.issue_detail["curation_items"]
        self.assertEqual(impact.base_purl, item["purl"])
        self.assertIn("both affected and fixed: 3.0.0", item["conflict_reason"])
        self.assertEqual(1, item["all_versions"].count("3.0.0"))
        self.assertNotIn("3.0.0", item["partial_curation"]["affected"])
        self.assertNotIn("3.0.0", item["partial_curation"]["fixing"])
        self.assertEqual(advisory.avid, item["advisories"][0]["primary"]["advisory_uid"])
        impact.refresh_from_db()
        self.assertTrue(impact.affecting_packages.filter(version="3.0.0").exists())
        self.assertTrue(impact.fixed_by_packages.filter(version="3.0.0").exists())

    def test_distinct_affected_and_fixed_versions_do_not_create_todo(self):
        self.advisory_data.affected_packages[0].fixed_version_range = VersionRange.from_string(
            "vers:npm/3.1.0"
        )
        self.insert_advisory()

        ComputeToDo().execute()

        self.assertFalse(AdvisoryToDoV2.objects.exists())

    def test_same_version_for_different_packages_does_not_create_todo(self):
        self.advisory_data.affected_packages = [
            AffectedPackageV2(
                package=PackageURL(type="npm", name="express-restify-mongoose"),
                affected_version_range=VersionRange.from_string("vers:npm/3.0.0"),
            ),
            AffectedPackageV2(
                package=PackageURL(type="npm", name="another-package"),
                fixed_version_range=VersionRange.from_string("vers:npm/3.0.0"),
            ),
        ]
        self.insert_advisory()

        ComputeToDo().execute()

        self.assertFalse(AdvisoryToDoV2.objects.exists())

    def test_detects_conflict_across_impacts_for_the_same_package(self):
        package = PackageURL(type="npm", name="express-restify-mongoose")
        self.advisory_data.affected_packages = [
            AffectedPackageV2(
                package=package,
                affected_version_range=VersionRange.from_string("vers:npm/3.0.0"),
            ),
            AffectedPackageV2(
                package=package,
                fixed_version_range=VersionRange.from_string("vers:npm/3.0.0"),
            ),
        ]
        self.insert_advisory()

        ComputeToDo().execute()

        todo = AdvisoryToDoV2.objects.get()
        self.assertEqual(
            ["3.0.0"],
            todo.issue_detail["conflict_details"][str(package)]["conflicting_versions"],
        )

    def test_repeated_pipeline_runs_do_not_duplicate_todo_or_relations(self):
        self.insert_advisory()
        ComputeToDo().execute()
        todo = AdvisoryToDoV2.objects.get()
        original_detail = todo.issue_detail
        created_at = todo.created_at

        ComputeToDo().execute()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual(1, ToDoRelatedAdvisoryV2.objects.count())

        todo.is_resolved = True
        todo.save()
        ComputeToDo().execute()

        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual(1, ToDoRelatedAdvisoryV2.objects.count())
        todo.refresh_from_db()
        self.assertTrue(todo.is_resolved)
        self.assertEqual(original_detail, todo.issue_detail)
        self.assertEqual(created_at, todo.created_at)

    def test_other_todo_does_not_hide_version_conflict(self):
        self.advisory_data.summary = ""
        advisory = self.insert_advisory()
        advisory._all_impacts_unfurled_at = timezone.now()
        advisory.save()

        ComputeToDo().execute()

        self.assertEqual(
            {"MISSING_SUMMARY", "CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES"},
            set(advisory.advisory_todos.values_list("issue_type", flat=True)),
        )

    def test_non_latest_advisory_does_not_create_todo(self):
        advisory = self.insert_advisory()
        advisory.is_latest = False
        advisory.save()

        ComputeToDo().execute()

        self.assertFalse(AdvisoryToDoV2.objects.exists())

    @patch("vulnerabilities.importers.TODO_EXCLUDED_PIPELINES", ["test_pipeline"])
    def test_excluded_pipeline_does_not_create_todo(self):
        self.insert_advisory()

        ComputeToDo().execute()

        self.assertFalse(AdvisoryToDoV2.objects.exists())

    def test_group_todo_does_not_hide_conflicts_within_individual_advisories(self):
        advisory = self.insert_advisory()
        self.advisory_data.advisory_id = "93"
        other_advisory = self.insert_advisory()
        group_todo = AdvisoryToDoV2.objects.create(
            related_advisories_id=advisories_checksum([advisory, other_advisory]),
            issue_type="CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES",
            advisories_count=2,
            alias="test_alias",
        )
        group_todo.advisories.add(advisory, other_advisory)

        ComputeToDo().execute()

        self.assertEqual(3, AdvisoryToDoV2.objects.count())
        self.assertEqual(2, AdvisoryToDoV2.objects.filter(advisories_count=1).count())
        self.assertEqual(2, group_todo.advisories.count())

    def test_package_type_without_range_scheme_still_creates_todo(self):
        self.advisory_data.affected_packages = [
            AffectedPackageV2(
                package=PackageURL(type="docker", name="example"),
                affected_version_range=VersionRange.from_string("vers:generic/3.0.0"),
                fixed_version_range=VersionRange.from_string("vers:generic/3.0.0"),
            )
        ]
        self.insert_advisory()

        ComputeToDo().execute()

        todo = AdvisoryToDoV2.objects.get()
        (item,) = todo.issue_detail["curation_items"]
        self.assertEqual("pkg:docker/example", item["purl"])
        self.assertEqual(["3.0.0"], item["all_versions"])


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
