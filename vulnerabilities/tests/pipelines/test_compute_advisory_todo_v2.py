#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime

from django.test import TestCase
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryToDoV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.pipelines.v2_improvers.compute_advisory_todo import ComputeToDo


class TestComputeToDo(TestCase):
    def setUp(self):
        self.advisory_data1 = AdvisoryDataV2(
            advisory_id="test_id",
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range="vers:npm/>=1.0.0|<2.0.0",
                    fixed_version_range="vers:npm/2.0.0",
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
                    affected_version_range="vers:npm/>=1.0.0|<2.0.0",
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
                    fixed_version_range="vers:npm/2.0.0",
                )
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data4 = AdvisoryDataV2(
            advisory_id="test_id_3",
            summary="Test summary",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range="vers:npm/>=1.0.0|<=2.0.0",
                    fixed_version_range="vers:npm/2.0.1",
                )
            ],
            references=[ReferenceV2(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

    def test_advisory_todo_missing_summary(self):
        date = datetime.now()
        adv = AdvisoryV2.objects.create(
            unique_content_id="test_id",
            url=self.advisory_data1.url,
            summary="",
            date_collected=date,
            advisory_id="test_id",
            avid="test_pipeline/test_id",
            datasource_id="test_pipeline",
        )
        for pkg in self.advisory_data1.affected_packages:
            ImpactedPackage.objects.create(
                advisory=adv,
                base_purl=pkg.package,
                affecting_vers=pkg.affected_version_range,
                fixed_vers=pkg.fixed_version_range,
            )
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_SUMMARY", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_missing_fixed(self):
        date = datetime.now()
        adv = AdvisoryV2.objects.create(
            unique_content_id="test_id",
            url=self.advisory_data2.url,
            summary=self.advisory_data2.summary,
            date_collected=date,
            advisory_id="test_id",
            avid="test_pipeline/test_id",
            datasource_id="test_pipeline",
        )
        for pkg in self.advisory_data2.affected_packages:
            ImpactedPackage.objects.create(
                advisory=adv,
                base_purl=pkg.package,
                affecting_vers=pkg.affected_version_range,
                fixed_vers=pkg.fixed_version_range or "",
            )
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_FIXED_BY_PACKAGE", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_missing_affected(self):
        date = datetime.now()
        adv = AdvisoryV2.objects.create(
            unique_content_id="test_id",
            url=self.advisory_data3.url,
            summary=self.advisory_data3.summary,
            date_collected=date,
            advisory_id="test_id",
            avid="test_pipeline/test_id",
            datasource_id="test_pipeline",
        )
        for pkg in self.advisory_data3.affected_packages:
            ImpactedPackage.objects.create(
                advisory=adv,
                base_purl=pkg.package,
                affecting_vers=pkg.affected_version_range or "",
                fixed_vers=pkg.fixed_version_range,
            )
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("MISSING_AFFECTED_PACKAGE", todo.issue_type)
        self.assertEqual(1, todo.advisories.count())

    def test_advisory_todo_conflicting_fixed_affected(self):
        alias = AdvisoryAlias.objects.create(alias="CVE-0000-0000")
        date = datetime.now()
        adv1 = AdvisoryV2.objects.create(
            unique_content_id="test_id1",
            url=self.advisory_data1.url,
            summary=self.advisory_data1.summary,
            date_collected=date,
            advisory_id="test_id",
            avid="test_pipeline/test_id_2",
            datasource_id="test_pipeline",
        )
        for pkg in self.advisory_data1.affected_packages:
            ImpactedPackage.objects.create(
                advisory=adv1,
                base_purl=pkg.package,
                affecting_vers=pkg.affected_version_range or "",
                fixed_vers=pkg.fixed_version_range or "",
            )
        adv1.aliases.add(alias)
        adv2 = AdvisoryV2.objects.create(
            unique_content_id="test_id2",
            url=self.advisory_data4.url,
            summary=self.advisory_data4.summary,
            date_collected=date,
            advisory_id="test_id",
            avid="test_pipeline/test_id_2",
            datasource_id="test_pipeline",
        )
        for pkg in self.advisory_data4.affected_packages:
            ImpactedPackage.objects.create(
                advisory=adv2,
                base_purl=pkg.package,
                affecting_vers=pkg.affected_version_range or "",
                fixed_vers=pkg.fixed_version_range or "",
            )
        adv2.aliases.add(alias)

        self.assertEqual(0, AdvisoryToDoV2.objects.count())
        pipeline = ComputeToDo()
        pipeline.execute()

        todo = AdvisoryToDoV2.objects.first()
        self.assertEqual(1, AdvisoryToDoV2.objects.count())
        self.assertEqual("CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES", todo.issue_type)
        self.assertIn(
            "CVE-0000-0000: pkg:npm/package1 with conflicting fixed version", todo.issue_detail
        )
        self.assertEqual(2, todo.advisories.count())
        self.assertEqual(todo, adv2.advisory_todos.first())
