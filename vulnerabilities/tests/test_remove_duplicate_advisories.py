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

import pytest
import pytz
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.models import Advisory
from vulnerabilities.pipelines.remove_duplicate_advisories import RemoveDuplicateAdvisoriesPipeline


@pytest.fixture
def advisory_data():
    return AdvisoryData(
        summary="Test summary",
        affected_packages=[
            AffectedPackage(
                package=PackageURL(type="npm", name="package1"),
                affected_version_range=NpmVersionRange(
                    constraints=[
                        VersionConstraint(comparator=">=", version=SemverVersion("1.0.0")),
                        VersionConstraint(comparator="<", version=SemverVersion("2.0.0")),
                    ]
                ),
            )
        ],
        references=[Reference(url="https://example.com/vuln1")],
    )


@pytest.mark.django_db
def test_remove_duplicates_keeps_oldest(advisory_data):
    """
    Test that when multiple advisories have the same content,
    only the oldest one is kept.
    """
    dates = [
        datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        datetime.datetime(2024, 1, 2, tzinfo=pytz.UTC),
        datetime.datetime(2024, 1, 3, tzinfo=pytz.UTC),
    ]

    for date in dates:
        Advisory.objects.create(
            summary=advisory_data.summary,
            affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
            references=[ref.to_dict() for ref in advisory_data.references],
            date_imported=date,
            date_collected=date,
        )

    Advisory.objects.create(
        summary="Test summary 21",
        affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
        references=[ref.to_dict() for ref in advisory_data.references],
        date_imported=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
    )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 0  # Simulate 4 workers with keep_available=0
        pipeline = RemoveDuplicateAdvisoriesPipeline()
        pipeline.remove_duplicates()

    # Check that only the oldest advisory remains
    remaining = Advisory.objects.all()
    assert remaining.count() == 2
    assert remaining.first().date_imported == dates[0]


@pytest.mark.django_db
def test_remove_duplicates_keeps_oldest_async(advisory_data):
    """
    Test that when multiple advisories have the same content,
    only the oldest one is kept.
    """
    dates = [
        datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        datetime.datetime(2024, 1, 2, tzinfo=pytz.UTC),
        datetime.datetime(2024, 1, 3, tzinfo=pytz.UTC),
    ]

    for date in dates:
        Advisory.objects.create(
            summary=advisory_data.summary,
            affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
            references=[ref.to_dict() for ref in advisory_data.references],
            date_imported=date,
            date_collected=date,
        )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 4  # Simulate 4 workers with keep_available=0
        pipeline = RemoveDuplicateAdvisoriesPipeline()
        pipeline.remove_duplicates()

    # Check that only the oldest advisory remains
    remaining = Advisory.objects.all()
    assert remaining.count() == 1
    assert remaining.first().date_imported == dates[0]


@pytest.mark.django_db
def test_different_content_preserved():
    """
    Test that advisories with different content are preserved.
    """
    date = datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC)

    Advisory.objects.create(
        summary="Summary 1",
        affected_packages=[],
        references=[],
        date_collected=date,
        date_imported=date,
    )

    Advisory.objects.create(
        summary="Summary 2",
        affected_packages=[],
        references=[],
        date_collected=date,
        date_imported=date,
    )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 4  # Simulate 4 workers with keep_available=0

        pipeline = RemoveDuplicateAdvisoriesPipeline()
        pipeline.remove_duplicates()

    # Check that both advisories remain
    assert Advisory.objects.count() == 2


@pytest.mark.django_db
def test_remove_duplicates_with_multiple_batches(advisory_data):
    """
    Test that duplicate removal works correctly across multiple batches.
    """
    # Create enough duplicates to span multiple batches
    dates = [
        datetime.datetime(
            2024 + (i // (12 * 28)),  # Year
            ((i // 28) % 12) + 1,  # Month (1-12)
            (i % 28) + 1,  # Day (1-28)
            tzinfo=pytz.UTC,
        )
        for i in range(100)
    ]

    for date in dates:
        Advisory.objects.create(
            summary=advisory_data.summary,
            affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
            references=[ref.to_dict() for ref in advisory_data.references],
            date_imported=date,
            date_collected=date,
        )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 4  # Simulate 4 workers with keep_available=0

        pipeline = RemoveDuplicateAdvisoriesPipeline()
        pipeline.BATCH_SIZE = 1000  # Ensure multiple batches
        pipeline.remove_duplicates()

    # Check that only one advisory remains
    remaining = Advisory.objects.all()
    assert remaining.count() == 1
    assert remaining.first().date_imported == dates[0]


@pytest.mark.django_db
def test_remove_duplicates_with_multiple_batches_no_workers(advisory_data):
    """
    Test that duplicate removal works correctly across multiple batches.
    """
    # Create enough duplicates to span multiple batches
    dates = [
        datetime.datetime(
            2024 + (i // (12 * 28)),  # Year
            ((i // 28) % 12) + 1,  # Month (1-12)
            (i % 28) + 1,  # Day (1-28)
            tzinfo=pytz.UTC,
        )
        for i in range(100)  # Create 100 advisories
    ]

    for date in dates:
        Advisory.objects.create(
            summary=advisory_data.summary,
            affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
            references=[ref.to_dict() for ref in advisory_data.references],
            date_imported=date,
            date_collected=date,
        )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 0  # Simulate 0 workers with keep_available=0

        pipeline = RemoveDuplicateAdvisoriesPipeline()
        pipeline.BATCH_SIZE = 1000  # Ensure multiple batches
        pipeline.remove_duplicates()

    # Check that only one advisory remains
    remaining = Advisory.objects.all()
    assert remaining.count() == 1
    assert remaining.first().date_imported == dates[0]


@pytest.mark.django_db
def test_remove_duplicates_error_handling(advisory_data):
    """
    Test error handling during duplicate removal.
    """
    date = datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC)

    Advisory.objects.create(
        summary=advisory_data.summary,
        affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
        references=[ref.to_dict() for ref in advisory_data.references],
        date_imported=date,
        date_collected=date,
    )

    with patch("django.db.transaction.atomic") as mock_atomic:
        mock_atomic.side_effect = Exception("Test error")

        with patch(
            "vulnerabilities.pipelines.recompute_content_ids.get_max_workers"
        ) as mock_workers:
            mock_workers.return_value = 4  # Simulate 4 workers with keep_available=0

            pipeline = RemoveDuplicateAdvisoriesPipeline()
            pipeline.remove_duplicates()
