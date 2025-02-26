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
from vulnerabilities.pipelines.recompute_content_ids import RecomputeContentIDPipeline


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
def test_recompute_content_ids_basic_async(advisory_data):
    """
    Test that advisories without content IDs get them computed.
    """
    advisory = Advisory.objects.create(
        summary=advisory_data.summary,
        affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
        references=[ref.to_dict() for ref in advisory_data.references],
        unique_content_id="",
        date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
    )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 4

        pipeline = RecomputeContentIDPipeline()
        pipeline.recompute_content_ids()

    advisory.refresh_from_db()
    assert advisory.unique_content_id != ""
    assert len(advisory.unique_content_id) == 64  # SHA256 hash length


@pytest.mark.django_db
def test_recompute_content_ids_multiple_batches_async(advisory_data):
    """
    Test that content ID computation works across multiple batches.
    """
    dates = [
        datetime.datetime(
            2024 + (i // (12 * 28)),  # Year
            ((i // 28) % 12) + 1,  # Month (1-12)
            (i % 28) + 1,  # Day (1-28)
            tzinfo=pytz.UTC,
        )
        for i in range(2500)  # Create 2500 advisories
    ]

    for date in dates:
        Advisory.objects.create(
            summary=advisory_data.summary,
            affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
            references=[ref.to_dict() for ref in advisory_data.references],
            unique_content_id="",
            date_imported=date,
            date_collected=date,
        )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 4

        pipeline = RecomputeContentIDPipeline()
        pipeline.BATCH_SIZE = 1000
        pipeline.recompute_content_ids()

    assert not Advisory.objects.filter(unique_content_id="").exists()
    assert Advisory.objects.exclude(unique_content_id__length=64).count() == 0


@pytest.mark.django_db
def test_recompute_content_ids_basic(advisory_data):
    """
    Test that advisories without content IDs get them computed.
    """
    advisory = Advisory.objects.create(
        summary=advisory_data.summary,
        affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
        references=[ref.to_dict() for ref in advisory_data.references],
        unique_content_id="",
        date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
    )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 0

        pipeline = RecomputeContentIDPipeline()
        pipeline.recompute_content_ids()

    advisory.refresh_from_db()
    assert advisory.unique_content_id != ""
    assert len(advisory.unique_content_id) == 64  # SHA256 hash length


@pytest.mark.django_db
def test_recompute_content_ids_multiple_batches(advisory_data):
    """
    Test that content ID computation works across multiple batches.
    """
    dates = [
        datetime.datetime(
            2024 + (i // (12 * 28)),  # Year
            ((i // 28) % 12) + 1,  # Month (1-12)
            (i % 28) + 1,  # Day (1-28)
            tzinfo=pytz.UTC,
        )
        for i in range(2500)  # Create 2500 advisories
    ]

    for date in dates:
        Advisory.objects.create(
            summary=advisory_data.summary,
            affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
            references=[ref.to_dict() for ref in advisory_data.references],
            unique_content_id="",
            date_imported=date,
            date_collected=date,
        )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 0

        pipeline = RecomputeContentIDPipeline()
        pipeline.BATCH_SIZE = 1000
        pipeline.recompute_content_ids()

    assert not Advisory.objects.filter(unique_content_id="").exists()
    assert Advisory.objects.exclude(unique_content_id__length=64).count() == 0


@pytest.mark.django_db
def test_recompute_content_ids_preserves_existing(advisory_data):
    """
    Test that existing valid content IDs are preserved.
    """
    existing_content_id = "a" * 64  # Valid SHA256-length content ID

    advisory = Advisory.objects.create(
        summary=advisory_data.summary,
        affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
        references=[ref.to_dict() for ref in advisory_data.references],
        unique_content_id=existing_content_id,
        date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
    )

    with patch("vulnerabilities.pipelines.recompute_content_ids.get_max_workers") as mock_workers:
        mock_workers.return_value = 0

        pipeline = RecomputeContentIDPipeline()
        pipeline.recompute_content_ids()

    advisory.refresh_from_db()
    assert advisory.unique_content_id == existing_content_id


@pytest.mark.django_db
def test_recompute_content_ids_error_handling(advisory_data):
    """
    Test error handling during content ID computation.
    """
    Advisory.objects.create(
        summary=advisory_data.summary,
        affected_packages=[pkg.to_dict() for pkg in advisory_data.affected_packages],
        references=[ref.to_dict() for ref in advisory_data.references],
        unique_content_id="Test",
        date_collected=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
    )

    with patch("django.db.transaction.atomic") as mock_atomic:
        mock_atomic.side_effect = Exception("Test error")

        with patch(
            "vulnerabilities.pipelines.recompute_content_ids.get_max_workers"
        ) as mock_workers:
            mock_workers.return_value = 0

            pipeline = RecomputeContentIDPipeline()
            # expect an error
            with pytest.raises(Exception):
                pipeline.recompute_content_ids()
