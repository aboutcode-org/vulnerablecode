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

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.models import Advisory
from vulnerabilities.models import AdvisoryToDo
from vulnerabilities.models import Alias
from vulnerabilities.pipelines.compute_advisory_todo import ComputeToDo


class TestComputeToDo(TestCase):
    def setUp(self):
        self.advisory_data1 = AdvisoryData(
            summary="Test summary",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range="vers:npm/>=1.0.0|<2.0.0",
                    fixed_version="2.0.0",
                )
            ],
            references=[Reference(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data2 = AdvisoryData(
            summary="Test summary",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range="vers:npm/>=1.0.0|<2.0.0",
                )
            ],
            references=[Reference(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data3 = AdvisoryData(
            summary="Test summary",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(type="npm", name="package1"),
                    fixed_version="2.0.0",
                )
            ],
            references=[Reference(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

        self.advisory_data4 = AdvisoryData(
            summary="Test summary",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range="vers:npm/>=1.0.0|<=2.0.0",
                    fixed_version="2.0.1",
                )
            ],
            references=[Reference(url="https://example.com/vuln1")],
            url="https://test.url/",
        )

    def test_advisory_todo_missing_summary(self):
        date = datetime.now()
        Advisory.objects.create(
            unique_content_id="test_id",
            url=self.advisory_data1.url,
            summary="",
            affected_packages=[pkg.to_dict() for pkg in self.advisory_data1.affected_packages],
            references=[ref.to_dict() for ref in self.advisory_data1.references],
            date_imported=date,
            date_collected=date,
            created_by="test_pipeline",
        )
        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDo.objects.first()
        self.assertEqual(1, AdvisoryToDo.objects.count())
        self.assertEqual("MISSING_SUMMARY", todos.issue_type)

    def test_advisory_todo_missing_fixed(self):
        date = datetime.now()
        Advisory.objects.create(
            unique_content_id="test_id",
            url=self.advisory_data2.url,
            summary=self.advisory_data2.summary,
            affected_packages=[pkg.to_dict() for pkg in self.advisory_data2.affected_packages],
            references=[ref.to_dict() for ref in self.advisory_data2.references],
            date_imported=date,
            date_collected=date,
            created_by="test_pipeline",
        )
        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDo.objects.first()
        self.assertEqual(1, AdvisoryToDo.objects.count())
        self.assertEqual("MISSING_FIXED_BY_PACKAGE", todos.issue_type)

    def test_advisory_todo_missing_affected(self):
        date = datetime.now()
        Advisory.objects.create(
            unique_content_id="test_id",
            url=self.advisory_data3.url,
            summary=self.advisory_data3.summary,
            affected_packages=[pkg.to_dict() for pkg in self.advisory_data3.affected_packages],
            references=[ref.to_dict() for ref in self.advisory_data3.references],
            date_imported=date,
            date_collected=date,
            created_by="test_pipeline",
        )
        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDo.objects.first()
        self.assertEqual(1, AdvisoryToDo.objects.count())
        self.assertEqual("MISSING_AFFECTED_PACKAGE", todos.issue_type)

    def test_advisory_todo_conflicting_fixed_affected(self):
        alias = Alias.objects.create(alias="CVE-0000-0000")
        date = datetime.now()
        adv1 = Advisory.objects.create(
            unique_content_id="test_id1",
            url=self.advisory_data1.url,
            summary=self.advisory_data1.summary,
            affected_packages=[pkg.to_dict() for pkg in self.advisory_data1.affected_packages],
            references=[ref.to_dict() for ref in self.advisory_data1.references],
            date_imported=date,
            date_collected=date,
            created_by="test_pipeline",
        )
        adv1.aliases.add(alias)
        adv2 = Advisory.objects.create(
            unique_content_id="test_id2",
            url=self.advisory_data4.url,
            summary=self.advisory_data4.summary,
            affected_packages=[pkg.to_dict() for pkg in self.advisory_data4.affected_packages],
            references=[ref.to_dict() for ref in self.advisory_data4.references],
            date_imported=date,
            date_collected=date,
            created_by="test_pipeline",
        )
        adv2.aliases.add(alias)

        pipeline = ComputeToDo()
        pipeline.execute()

        todos = AdvisoryToDo.objects.first()
        self.assertEqual(1, AdvisoryToDo.objects.count())
        self.assertEqual("CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES", todos.issue_type)
        self.assertIn(
            "CVE-0000-0000: pkg:npm/package1 with conflicting fixed version", todos.issue_detail
        )
