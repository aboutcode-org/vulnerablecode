#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
from unittest.mock import patch

import pytz
from django.test import TestCase
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.models import Advisory
from vulnerabilities.pipelines.remove_duplicate_advisories import RemoveDuplicateAdvisoriesPipeline


class TestRemoveDuplicateAdvisoriesPipeline(TestCase):
    def setUp(self):
        self.advisory_data = AdvisoryData(
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

    def test_remove_duplicates_keeps_oldest(self):
        """
        Test that when multiple advisories have the same content,
        only the oldest one is kept.
        """
        from vulnerabilities.utils import compute_content_id

        # Create three advisories with same content but different dates
        dates = [
            datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            datetime.datetime(2024, 1, 2, tzinfo=pytz.UTC),
            datetime.datetime(2024, 1, 3, tzinfo=pytz.UTC),
        ]

        advisories = []
        for i, date in enumerate(dates):
            advisory = Advisory.objects.create(
                unique_content_id=f"incorrect-content-id{i}",
                url=self.advisory_data.url,
                summary=self.advisory_data.summary,
                affected_packages=[pkg.to_dict() for pkg in self.advisory_data.affected_packages],
                references=[ref.to_dict() for ref in self.advisory_data.references],
                date_imported=date,
                date_collected=date,
                created_by="test_pipeline",
            )
            advisories.append(advisory)

        # Run the pipeline
        pipeline = RemoveDuplicateAdvisoriesPipeline()
        pipeline.execute()

        # Check that only the first advisory remains
        remaining = Advisory.objects.all()
        self.assertEqual(remaining.count(), 1)
        self.assertEqual(remaining.first().date_imported, dates[0])

    def test_different_content_preserved(self):
        """
        Test that advisories with different content are preserved.
        """
        # Create two advisories with different content
        advisory1 = Advisory.objects.create(
            unique_content_id="test-id1",
            url="https://test.url/",
            summary="Summary 1",
            affected_packages=[],
            date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            references=[],
            date_imported=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            created_by="test_pipeline",
        )

        advisory2 = Advisory.objects.create(
            unique_content_id="test-id2",
            url="https://test.url/",
            summary="Summary 2",
            affected_packages=[],
            references=[],
            date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            date_imported=datetime.datetime(2024, 1, 2, tzinfo=pytz.UTC),
            created_by="test_pipeline",
        )

        # Run the pipeline
        pipeline = RemoveDuplicateAdvisoriesPipeline()
        pipeline.execute()

        # Check that both advisories remain
        self.assertEqual(Advisory.objects.count(), 2)

    def test_recompute_content_ids(self):
        """
        Test that advisories without content IDs get them updated.
        """
        from vulnerabilities.utils import compute_content_id

        # Create advisory without content ID
        advisory = Advisory.objects.create(
            unique_content_id="incorrect-content-id",
            url=self.advisory_data.url,
            summary=self.advisory_data.summary,
            affected_packages=[pkg.to_dict() for pkg in self.advisory_data.affected_packages],
            references=[ref.to_dict() for ref in self.advisory_data.references],
            date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
            created_by="test_pipeline",
        )

        # Run the pipeline
        pipeline = RemoveDuplicateAdvisoriesPipeline()
        pipeline.execute()

        # Check that content ID was updated
        advisory.refresh_from_db()
        expected_content_id = compute_content_id(advisory_data=self.advisory_data)
        self.assertEqual(advisory.unique_content_id, expected_content_id)
