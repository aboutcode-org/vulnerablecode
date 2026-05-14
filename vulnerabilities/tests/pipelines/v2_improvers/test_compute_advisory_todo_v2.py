#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from datetime import datetime

from django.test import TestCase
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.models import AdvisoryToDoV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.pipelines.v2_improvers.compute_advisory_todo import ComputeToDo
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.tests.pipelines import TestLogger


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

    def test_advisory_todo_missing_summary(self):
        insert_advisory_v2(
            advisory=self.advisory_data1,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
        )
        adv = AdvisoryV2.objects.first()
        adv.summary = ""
        adv.save()
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_SUMMARY", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_missing_fixed(self):
        insert_advisory_v2(
            advisory=self.advisory_data2,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
        )
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_FIXED_BY_PACKAGE", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_missing_affected(self):
        insert_advisory_v2(
            advisory=self.advisory_data3,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
        )
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_AFFECTED_PACKAGE", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_conflicting_fixed_affected(self):
        insert_advisory_v2(
            advisory=self.advisory_data1,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
        )
        insert_advisory_v2(
            advisory=self.advisory_data4,
            pipeline_id="test_pipeline2",
            logger=self.log.write,
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
            '"conflict_checksum": "57f32de5f41f137f0e3808535c2d974d54eeeda426c4279e7fb90475d26f0313",',
            todo.issue_detail,
        )
        self.assertEqual(2, todo.advisories.count())
        self.assertEqual(todo, adv.advisory_todos.first())

    def test_todo_at_package_alias_intersection(self):
        insert_advisory_v2(
            advisory=self.advisory_data4,
            pipeline_id="test_pipeline4",
            logger=self.log.write,
        )
        insert_advisory_v2(
            advisory=self.advisory_data5,
            pipeline_id="test_pipeline5",
            logger=self.log.write,
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
            "summary": "('test_pipeline5/test_id_5', 'test_pipeline6/test_id_6'): Test summary",
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
                    "affected_version_range": "vers:npm/>=1.0.0|<=2.0.0",
                    "fixed_version_range": "vers:npm/2.0.1",
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
        )
        insert_advisory_v2(
            advisory=self.advisory_data6,
            pipeline_id="test_pipeline6",
            logger=self.log.write,
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        issue_details = json.loads(todo.issue_detail)
        result_partial_curation = issue_details["partial_curation_advisory"]
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertDictEqual(expected_partial_curation_advisory, result_partial_curation)

    def test_todo_conflict_details_partial_curation_unpaired_purl_and_conflicting_affected_and_fixed(
        self,
    ):
        expected_partial_curation_advisory = {
            "advisory_id": "PLACEHOLDER_PARTIAL_CURATION_AVID",
            "aliases": ["CVE-000-000"],
            "summary": "('test_pipeline1/test_id', 'test_pipeline5/test_id_5'): Test summary",
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
        )
        insert_advisory_v2(
            advisory=self.advisory_data1,
            pipeline_id="test_pipeline1",
            logger=self.log.write,
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        issue_details = json.loads(todo.issue_detail)
        result_partial_curation = issue_details["partial_curation_advisory"]
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertDictEqual(expected_partial_curation_advisory, result_partial_curation)

    def test_todo_conflict_details_partial_curation_unpaired_purl_and_conflicting_fixed(self):
        expected_partial_curation_advisory = {
            "advisory_id": "PLACEHOLDER_PARTIAL_CURATION_AVID",
            "aliases": ["CVE-000-000"],
            "summary": "('test_pipeline1/test_id', 'test_pipeline7/test_id_5'): Test summary",
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
        )
        insert_advisory_v2(
            advisory=self.advisory_data7,
            pipeline_id="test_pipeline7",
            logger=self.log.write,
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        issue_details = json.loads(todo.issue_detail)
        result_partial_curation = issue_details["partial_curation_advisory"]
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertDictEqual(expected_partial_curation_advisory, result_partial_curation)

    def test_todo_conflict_details_partial_curation_unpaired_purl_and_conflicting_affected(self):
        expected_partial_curation_advisory = {
            "advisory_id": "PLACEHOLDER_PARTIAL_CURATION_AVID",
            "aliases": ["CVE-000-000"],
            "summary": "('test_pipeline1/test_id', 'test_pipeline7/test_id_5'): Test summary",
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
            pipeline_id="test_pipeline1",
            logger=self.log.write,
        )
        insert_advisory_v2(
            advisory=self.advisory_data8,
            pipeline_id="test_pipeline7",
            logger=self.log.write,
        )
        for imp in ImpactedPackage.objects.all():
            imp.last_successful_range_unfurl_at = datetime.now()
            imp.save()

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        issue_details = json.loads(todo.issue_detail)
        result_partial_curation = issue_details["partial_curation_advisory"]
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_AFFECTED_PACKAGES", todo.issue_type)
        self.assertDictEqual(expected_partial_curation_advisory, result_partial_curation)
