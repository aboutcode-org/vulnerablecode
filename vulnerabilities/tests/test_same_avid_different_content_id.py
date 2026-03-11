#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import uuid
from datetime import timedelta

import pytest
from django.utils.timezone import now

from vulnerabilities.models import AdvisoryV2


@pytest.fixture
def advisory_factory(db):
    """
    Factory to create AdvisoryV2 objects with minimal required fields.
    """

    def _create(*, avid, advisory_id, collected_at):
        return AdvisoryV2.objects.create(
            datasource_id="test_source",
            advisory_id=advisory_id,
            avid=avid,
            unique_content_id=str(uuid.uuid4()),
            url="https://example.com/advisory",
            date_collected=collected_at,
        )

    return _create


@pytest.fixture
def timestamps():
    now_ts = now()
    return {
        "old": now_ts - timedelta(days=3),
        "mid": now_ts - timedelta(days=1),
        "new": now_ts,
    }


@pytest.mark.django_db
def test_latest_for_avid_returns_latest_by_date_collected(
    advisory_factory, timestamps, django_assert_num_queries
):
    avid = "source/ADV-1"

    older = advisory_factory(
        avid=avid,
        advisory_id="ADV-1",
        collected_at=timestamps["old"],
    )
    newer = advisory_factory(
        avid=avid,
        advisory_id="ADV-1",
        collected_at=timestamps["new"],
    )

    with django_assert_num_queries(1):
        result = AdvisoryV2.objects.latest_for_avid(avid)

    assert result.id == newer.id
    assert result.id != older.id


@pytest.mark.django_db
def test_latest_for_avid_tie_breaks_by_id(advisory_factory, timestamps, django_assert_num_queries):
    avid = "source/ADV-2"
    ts = timestamps["mid"]

    first = advisory_factory(
        avid=avid,
        advisory_id="ADV-2",
        collected_at=ts,
    )
    second = advisory_factory(
        avid=avid,
        advisory_id="ADV-2",
        collected_at=ts,
    )

    with django_assert_num_queries(1):
        result = AdvisoryV2.objects.latest_for_avid(avid)

    assert result.id == second.id


@pytest.mark.django_db
def test_latest_per_avid_returns_one_row_per_avid(
    advisory_factory, timestamps, django_assert_num_queries
):
    advisory_factory(
        avid="source/A",
        advisory_id="A",
        collected_at=timestamps["old"],
    )
    latest_a = advisory_factory(
        avid="source/A",
        advisory_id="A",
        collected_at=timestamps["new"],
    )

    latest_b = advisory_factory(
        avid="source/B",
        advisory_id="B",
        collected_at=timestamps["mid"],
    )

    with django_assert_num_queries(1):
        qs = AdvisoryV2.objects.latest_per_avid()
        results = list(qs)

    assert len(results) == 2
    ids = {obj.id for obj in results}
    assert ids == {latest_a.id, latest_b.id}


@pytest.mark.django_db
def test_latest_per_avid_excludes_older_versions(advisory_factory, timestamps):
    avid = "source/C"

    older = advisory_factory(
        avid=avid,
        advisory_id="C",
        collected_at=timestamps["old"],
    )
    latest = advisory_factory(
        avid=avid,
        advisory_id="C",
        collected_at=timestamps["new"],
    )

    results = list(AdvisoryV2.objects.latest_per_avid())

    assert latest in results
    assert older not in results


@pytest.mark.django_db
def test_latest_for_avids_filters_and_collapses_correctly(
    advisory_factory, timestamps, django_assert_num_queries
):
    advisory_factory(
        avid="source/A",
        advisory_id="A",
        collected_at=timestamps["old"],
    )
    latest_a = advisory_factory(
        avid="source/A",
        advisory_id="A",
        collected_at=timestamps["new"],
    )

    latest_b = advisory_factory(
        avid="source/B",
        advisory_id="B",
        collected_at=timestamps["mid"],
    )

    advisory_factory(
        avid="source/C",
        advisory_id="C",
        collected_at=timestamps["new"],
    )

    with django_assert_num_queries(1):
        qs = AdvisoryV2.objects.latest_for_avids({"source/A", "source/B"})
        results = list(qs)

    assert len(results) == 2
    ids = {obj.id for obj in results}
    assert ids == {latest_a.id, latest_b.id}


@pytest.mark.django_db
def test_latest_for_avids_with_empty_input_returns_empty_queryset(django_assert_num_queries):
    with django_assert_num_queries(0):
        qs = AdvisoryV2.objects.latest_for_avids(set())
        assert qs.count() == 0
