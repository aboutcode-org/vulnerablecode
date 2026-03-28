#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from datetime import timezone

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

    def test_relate_advisories_by_aliases_creates_todo(self):
        """Two advisories from different datasources sharing an alias get flagged."""
        alias = AdvisoryAlias.objects.create(alias="CVE-2021-9999")
        date = datetime.now(timezone.utc)

        adv1 = AdvisoryV2.objects.create(
            unique_content_id="alias_test_id1",
            url="https://example.com/1",
            summary="A vulnerability in foo",
            date_collected=date,
            advisory_id="CVE-2021-9999",
            avid="nvd_importer/CVE-2021-9999",
            datasource_id="nvd_importer",
        )
        adv1.aliases.add(alias)

        adv2 = AdvisoryV2.objects.create(
            unique_content_id="alias_test_id2",
            url="https://example.com/2",
            summary="A vulnerability in foo package",
            date_collected=date,
            advisory_id="CVE-2021-9999",
            avid="github_osv_importer/CVE-2021-9999",
            datasource_id="github_osv_importer",
        )
        adv2.aliases.add(alias)

        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDoV2.objects.filter(issue_type="POTENTIALLY_RELATED_BY_ALIASES")
        self.assertEqual(1, todos.count())
        self.assertEqual(2, todos.first().advisories.count())

    def test_relate_advisories_by_aliases_same_datasource_not_flagged(self):
        """Two advisories from the same datasource sharing an alias are not flagged."""
        alias = AdvisoryAlias.objects.create(alias="CVE-2021-8888")
        date = datetime.now(timezone.utc)

        adv1 = AdvisoryV2.objects.create(
            unique_content_id="same_ds_id1",
            url="https://example.com/1",
            summary="Vulnerability in bar",
            date_collected=date,
            advisory_id="CVE-2021-8888",
            avid="nvd_importer/CVE-2021-8888-1",
            datasource_id="nvd_importer",
        )
        adv1.aliases.add(alias)

        adv2 = AdvisoryV2.objects.create(
            unique_content_id="same_ds_id2",
            url="https://example.com/2",
            summary="Vulnerability in bar package",
            date_collected=date,
            advisory_id="CVE-2021-8888",
            avid="nvd_importer/CVE-2021-8888-2",
            datasource_id="nvd_importer",
        )
        adv2.aliases.add(alias)

        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDoV2.objects.filter(issue_type="POTENTIALLY_RELATED_BY_ALIASES")
        self.assertEqual(0, todos.count())

    def test_detect_similar_summaries_creates_todo(self):
        """Two advisories from different datasources with similar summaries get flagged."""
        alias = AdvisoryAlias.objects.create(alias="CVE-2021-7777")
        date = datetime.now(timezone.utc)

        adv1 = AdvisoryV2.objects.create(
            unique_content_id="sim_sum_id1",
            url="https://example.com/1",
            summary="Buffer overflow in nginx version 1.2 allows remote code execution",
            date_collected=date,
            advisory_id="CVE-2021-7777",
            avid="nvd_importer/CVE-2021-7777",
            datasource_id="nvd_importer",
        )
        adv1.aliases.add(alias)

        adv2 = AdvisoryV2.objects.create(
            unique_content_id="sim_sum_id2",
            url="https://example.com/2",
            summary="Buffer overflow in nginx version 1.2 allows remote code execution.",
            date_collected=date,
            advisory_id="CVE-2021-7777",
            avid="debian_importer_v2/CVE-2021-7777",
            datasource_id="debian_importer_v2",
        )
        adv2.aliases.add(alias)

        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDoV2.objects.filter(issue_type="SIMILAR_SUMMARIES")
        self.assertEqual(1, todos.count())
        self.assertEqual(2, todos.first().advisories.count())
        self.assertIn("similarity_score", todos.first().issue_detail)

    def test_detect_similar_summaries_below_threshold_not_flagged(self):
        """Two advisories with very different summaries are not flagged."""
        alias = AdvisoryAlias.objects.create(alias="CVE-2021-6666")
        date = datetime.now(timezone.utc)

        adv1 = AdvisoryV2.objects.create(
            unique_content_id="diff_sum_id1",
            url="https://example.com/1",
            summary="Buffer overflow in nginx allows remote code execution",
            date_collected=date,
            advisory_id="CVE-2021-6666",
            avid="nvd_importer/CVE-2021-6666",
            datasource_id="nvd_importer",
        )
        adv1.aliases.add(alias)

        adv2 = AdvisoryV2.objects.create(
            unique_content_id="diff_sum_id2",
            url="https://example.com/2",
            summary="SQL injection vulnerability in Django ORM affects all versions before 3.2",
            date_collected=date,
            advisory_id="CVE-2021-6666",
            avid="debian_importer_v2/CVE-2021-6666",
            datasource_id="debian_importer_v2",
        )
        adv2.aliases.add(alias)

        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDoV2.objects.filter(issue_type="SIMILAR_SUMMARIES")
        self.assertEqual(0, todos.count())

    def test_detect_similar_summaries_empty_summary_skipped(self):
        """Advisories with empty summaries are not compared for similarity."""
        alias = AdvisoryAlias.objects.create(alias="CVE-2021-5555")
        date = datetime.now(timezone.utc)

        adv1 = AdvisoryV2.objects.create(
            unique_content_id="empty_sum_id1",
            url="https://example.com/1",
            summary="",
            date_collected=date,
            advisory_id="CVE-2021-5555",
            avid="nvd_importer/CVE-2021-5555",
            datasource_id="nvd_importer",
        )
        adv1.aliases.add(alias)

        adv2 = AdvisoryV2.objects.create(
            unique_content_id="empty_sum_id2",
            url="https://example.com/2",
            summary="Buffer overflow in nginx",
            date_collected=date,
            advisory_id="CVE-2021-5555",
            avid="debian_importer_v2/CVE-2021-5555",
            datasource_id="debian_importer_v2",
        )
        adv2.aliases.add(alias)

        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDoV2.objects.filter(issue_type="SIMILAR_SUMMARIES")
        self.assertEqual(0, todos.count())
