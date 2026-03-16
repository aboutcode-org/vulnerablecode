#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import patch

import pytest

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_improvers.compute_advisory_content_hash import (
    ComputeAdvisoryContentHash,
)

pytestmark = pytest.mark.django_db


@pytest.fixture
def advisory_factory():
    def _create(count, with_hash=False, start=0):
        objs = []
        for i in range(start, start + count):
            objs.append(
                AdvisoryV2(
                    summary=f"summary {i}",
                    advisory_content_hash="existing_hash" if with_hash else None,
                    unique_content_id=f"unique_id_{i}",
                    advisory_id=f"ADV-{i}",
                    datasource_id="ds",
                    avid=f"ds/ADV-{i}",
                    url=f"https://example.com/ADV-{i}",
                )
            )
        return AdvisoryV2.objects.bulk_create(objs)

    return _create


def run_pipeline():
    pipeline = ComputeAdvisoryContentHash()
    pipeline.compute_advisory_content_hash()


@patch(
    "vulnerabilities.pipelines.v2_improvers.compute_advisory_content_hash.compute_advisory_content"
)
def test_pipeline_updates_only_missing_hash(mock_compute, advisory_factory):
    advisory_factory(3, with_hash=False, start=0)
    advisory_factory(2, with_hash=True, start=100)

    mock_compute.return_value = "new_hash"

    run_pipeline()

    updated = AdvisoryV2.objects.filter(advisory_content_hash="new_hash").count()
    untouched = AdvisoryV2.objects.filter(advisory_content_hash="existing_hash").count()

    assert updated == 3
    assert untouched == 2
    assert mock_compute.call_count == 3


@patch(
    "vulnerabilities.pipelines.v2_improvers.compute_advisory_content_hash.compute_advisory_content"
)
def test_pipeline_bulk_update_batches(mock_compute, advisory_factory):
    advisory_factory(6000, with_hash=False)

    mock_compute.return_value = "batch_hash"

    run_pipeline()

    assert AdvisoryV2.objects.filter(advisory_content_hash="batch_hash").count() == 6000

    assert mock_compute.call_count == 6000


@patch(
    "vulnerabilities.pipelines.v2_improvers.compute_advisory_content_hash.compute_advisory_content"
)
def test_pipeline_no_advisories(mock_compute):
    run_pipeline()

    assert mock_compute.call_count == 0
