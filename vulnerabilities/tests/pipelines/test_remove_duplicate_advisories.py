#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
from pathlib import Path

import pytz
from django.test import TestCase
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.models import Advisory
from vulnerabilities.pipelines.remove_duplicate_advisories import RemoveDuplicateAdvisoriesPipeline
from vulnerabilities.tests.pipelines import TestLogger
from vulnerabilities.utils import compute_content_id


class RemoveDuplicateAdvisoriesPipelineTest(TestCase):
    def setUp(self):
        self.data = Path(__file__).parent.parent / "test_data"
        self.advisory_data = AdvisoryData(
            summary="Test summary",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(type="npm", name="package1"),
                    affected_version_range=">=1.0.0|<2.0.0",
                )
            ],
            references=[Reference(url="https://example.com/vuln1")],
        )

    def test_remove_duplicates_keeps_latest(self):
        """
        Test that when multiple advisories have the same content,
        only the latest one is kept.
        """
        logger = TestLogger()
        content_id = compute_content_id(self.advisory_data)[:31]

        # Create three advisories with same content but different dates
        dates = [
            datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            datetime.datetime(2024, 1, 2, tzinfo=pytz.UTC),
            datetime.datetime(2024, 1, 3, tzinfo=pytz.UTC),
        ]

        for date in dates:
            Advisory.objects.create(
                summary=self.advisory_data.summary,
                affected_packages=self.advisory_data.affected_packages,
                references=self.advisory_data.references,
                date_collected=date,
                date_imported=date,
                unique_content_id=content_id,
            )

        # Run the pipeline step directly
        pipeline = RemoveDuplicateAdvisoriesPipeline(logger=logger.write)
        pipeline.remove_duplicates()

        # Check that only the latest advisory remains
        remaining = Advisory.objects.all()
        self.assertEqual(remaining.count(), 1)
        self.assertEqual(remaining.first().date_imported, dates[-1])

        # Check logging
        expected_logs = [
            "Found 1 content IDs with duplicates",
            f"Kept advisory {remaining.first().id} and removed 2 duplicates for content ID {content_id}",
        ]
        for log in expected_logs:
            self.assertIn(log, logger.getvalue())

    def test_different_content_preserved(self):
        """
        Test that advisories with different content are preserved.
        """
        logger = TestLogger()

        # Create two advisories with different content
        Advisory.objects.create(
            summary="Summary 1",
            affected_packages=[],
            references=[],
            date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            date_imported=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            unique_content_id=compute_content_id(AdvisoryData(summary="Summary 1"))[:31],
        )

        Advisory.objects.create(
            summary="Summary 2",
            affected_packages=[],
            references=[],
            date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            date_imported=datetime.datetime(2024, 1, 2, tzinfo=pytz.UTC),
            unique_content_id=compute_content_id(AdvisoryData(summary="Summary 2"))[:31],
        )

        # Run the pipeline step directly
        pipeline = RemoveDuplicateAdvisoriesPipeline(logger=logger.write)
        pipeline.remove_duplicates()

        # Check that both advisories remain
        self.assertEqual(Advisory.objects.count(), 2)
        self.assertIn("Found 0 content IDs with duplicates", logger.getvalue())

    def test_update_content_ids(self):
        """
        Test that advisories without content IDs get them updated.
        """
        logger = TestLogger()

        # Create advisory without content ID
        advisory = Advisory.objects.create(
            summary=self.advisory_data.summary,
            affected_packages=self.advisory_data.affected_packages,
            references=self.advisory_data.references,
            unique_content_id="",
            date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        )

        # Run the pipeline step directly
        pipeline = RemoveDuplicateAdvisoriesPipeline(logger=logger.write)
        pipeline.update_content_ids()

        # Check that content ID was updated
        advisory.refresh_from_db()
        self.assertNotEqual(advisory.unique_content_id, "")

        # Check logging
        expected_logs = [
            "Found 1 advisories without content ID",
            f"Updated content ID for advisory {advisory.id}",
        ]
        for log in expected_logs:
            self.assertIn(log, logger.getvalue())
