#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest import mock

import pytest
from django.utils import timezone

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.pipelines.v2_improvers.mark_unfurl_version_range import (
    MarkUnfurlVersionRangePipeline,
)
from vulnerabilities.pipelines.v2_improvers.mark_unfurl_version_range import (
    complete_advisories_import,
)
from vulnerabilities.pipelines.v2_improvers.mark_unfurl_version_range import (
    latest_advisories_with_all_impacts_unfurled_attempted,
)
from vulnerabilities.pipelines.v2_improvers.mark_unfurl_version_range import (
    latest_advisories_with_all_impacts_unfurled_successfully,
)


@pytest.mark.django_db
class TestMarkAllImpactsUnfurledSuccessfully:
    @mock.patch(
        "vulnerabilities.pipelines.v2_improvers.mark_unfurl_version_range.complete_advisories_import",
        wraps=complete_advisories_import,
    )
    def test_marks_only_fully_successful_advisories(
        self,
        mock_complete_advisories_import,
    ):
        now = timezone.now()

        # Fully successful
        advisory_a = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="1",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/1",
            unique_content_id=f"121",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_a,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=now,
        )

        # Partial success
        advisory_b = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="2",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/2",
            unique_content_id=f"122",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_b,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        pipeline = MarkUnfurlVersionRangePipeline()

        pipeline.mark_all_impacts_unfurled()


@pytest.mark.django_db
class TestMarkAllImpactsUnfurlAttempted:
    @mock.patch(
        "vulnerabilities.pipelines.v2_improvers.mark_unfurl_version_range.complete_advisories_import"
    )
    def test_marks_only_fully_attempted_advisories(
        self,
        mock_complete_advisories_import,
    ):
        now = timezone.now()

        # All attempted
        advisory_a = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="2",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/2",
            unique_content_id=f"122",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_a,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_a,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=now,
        )

        # Not all attempted
        advisory_b = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="3",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/3",
            unique_content_id=f"123",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_b,
            last_range_unfurl_at=None,
            last_successful_range_unfurl_at=None,
        )

        pipeline = MarkUnfurlVersionRangePipeline()

        pipeline.mark_all_impacts_unfurled()

        ids = latest_advisories_with_all_impacts_unfurled_attempted(
            impacted_packages=ImpactedPackage.objects.all()
        )

        assert len(ids) == 1


@pytest.mark.django_db
class TestAttemptedBatching:
    @mock.patch(
        "vulnerabilities.pipelines.v2_improvers.mark_unfurl_version_range.complete_advisories_import"
    )
    def test_attempted_advisories_are_chunked_in_batches_of_100(
        self,
        mock_complete_advisories_import,
    ):
        now = timezone.now()

        advisories = []

        for i in range(250):
            adv = AdvisoryV2.objects.create(
                datasource_id="ghsa",
                advisory_id=str(i),
                pipeline_id="ghsa_importer_v2",
                avid=f"ghsa/{i}",
                unique_content_id=f"12{i}",
                url="https://example.com/advisory",
                date_collected="2025-07-01T00:00:00Z",
                precedence=1,
                is_latest=True,
                _all_impacts_unfurled_successfully_at=None,
            )

            advisories.append(adv)

            ImpactedPackage.objects.create(
                advisory=adv,
                base_purl="pkg:pypi/django",
                affecting_vers="<2.0",
                last_range_unfurl_at=now,
                last_successful_range_unfurl_at=None,
            )

        pipeline = MarkUnfurlVersionRangePipeline()

        pipeline.mark_all_impacts_unfurled()

        assert mock_complete_advisories_import.call_count == 1

        first_call_ids = mock_complete_advisories_import.call_args_list[0][1]["advisory_ids"]
        assert len(first_call_ids) == 250


@pytest.mark.django_db
class TestLatestAdvisoriesWithAllImpactsUnfurledSuccessfully:
    def test_returns_only_advisories_with_all_successful_impacts(self):
        now = timezone.now()

        # Advisory A
        # ALL impacts successful
        # SHOULD be returned
        advisory_a = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="1",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/1",
            unique_content_id="121",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_a,
            affecting_vers=">2.0.0",
            base_purl="pkg:pypi/django",
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=now,
        )

        # Advisory B
        # Partial success
        # SHOULD NOT be returned
        advisory_b = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="2",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/2",
            unique_content_id="122",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_b,
            affecting_vers=">2.0.0",
            base_purl="pkg:pypi/django",
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=now,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_b,
            affecting_vers=">2.0.0",
            base_purl="pkg:pypi/djangob",
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        # Advisory C
        # No attempts
        # SHOULD NOT be returned
        advisory_c = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="3",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/3",
            unique_content_id="123",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_c,
            affecting_vers=">2.0.0",
            base_purl="pkg:pypi/djangob",
            last_range_unfurl_at=None,
            last_successful_range_unfurl_at=None,
        )

        # Advisory D
        # All attempted but all failed
        # SHOULD NOT be returned
        advisory_d = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="4",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/4",
            unique_content_id="124",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_d,
            affecting_vers=">2.0.0",
            base_purl="pkg:pypi/djangob",
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_d,
            affecting_vers=">2.0.0",
            base_purl="pkg:pypi/djangoc",
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        qs = latest_advisories_with_all_impacts_unfurled_successfully(
            impacted_packages=ImpactedPackage.objects.all()
        )

        advisories_avids = list(AdvisoryV2.objects.filter(id__in=qs).values_list("avid", flat=True))

        assert advisories_avids == ["ghsa/1"]


@pytest.mark.django_db
class TestLatestAdvisoriesWithAllImpactsUnfurledAttempted:
    def test_returns_only_advisories_with_all_impacts_attempted(self):
        now = timezone.now()

        # Advisory A
        # All attempted successfully
        # SHOULD be returned
        advisory_a = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="4",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/4",
            unique_content_id="124",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_a,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=now,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_a,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=now,
        )

        # Advisory B
        # Partial success
        # BUT all attempted
        # SHOULD be returned
        advisory_b = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="5",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/5",
            unique_content_id="125",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_b,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=now,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_b,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        # Advisory C
        # One impact never attempted
        # SHOULD NOT be returned
        advisory_c = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="6",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/6",
            unique_content_id="126",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_c,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_c,
            last_range_unfurl_at=None,
            last_successful_range_unfurl_at=None,
        )

        # Advisory D
        # All attempted but failed
        # SHOULD be returned
        advisory_d = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id="7",
            pipeline_id="ghsa_importer_v2",
            avid=f"ghsa/7",
            unique_content_id="127",
            url="https://example.com/advisory",
            date_collected="2025-07-01T00:00:00Z",
            precedence=1,
            is_latest=True,
            _all_impacts_unfurled_successfully_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_d,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        ImpactedPackage.objects.create(
            advisory=advisory_d,
            last_range_unfurl_at=now,
            last_successful_range_unfurl_at=None,
        )

        qs = latest_advisories_with_all_impacts_unfurled_attempted(
            impacted_packages=ImpactedPackage.objects.all()
        )

        advisories_avids = list(AdvisoryV2.objects.filter(id__in=qs).values_list("avid", flat=True))

        assert advisories_avids == [
            "ghsa/4",
            "ghsa/5",
            "ghsa/7",
        ]
