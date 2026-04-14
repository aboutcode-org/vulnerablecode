#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.tests.pipelines import TestLogger

logger = TestLogger()


@pytest.fixture
def advisory_factory(db):
    """
    Factory to create AdvisoryV2 objects with minimal required fields.
    """

    def _create(*, advisory_id, summary):

        return insert_advisory_v2(
            advisory=AdvisoryDataV2(
                summary=summary,
                advisory_id=advisory_id,
                url="https://example.com/advisory",
            ),
            pipeline_id="source",
            logger=logger.write,
        )

    return _create


@pytest.mark.django_db
def test_latest_for_avid_returns_latest_by_date_collected(
    advisory_factory, django_assert_num_queries
):
    avid = "source/ADV-1"

    older = advisory_factory(advisory_id="ADV-1", summary="old advisory")
    newer = advisory_factory(advisory_id="ADV-1", summary="new advisory")

    with django_assert_num_queries(1):
        result = AdvisoryV2.objects.latest_for_avid(avid)

    assert result.id == newer.id
    assert result.id != older.id


@pytest.mark.django_db
def test_latest_for_avid_tie_breaks_by_id(advisory_factory, django_assert_num_queries):
    avid = "source/ADV-2"

    first = advisory_factory(advisory_id="ADV-2", summary="old advisory")
    second = advisory_factory(advisory_id="ADV-2", summary="new advisory")

    with django_assert_num_queries(1):
        result = AdvisoryV2.objects.latest_for_avid(avid)

    assert result.id == second.id


@pytest.mark.django_db
def test_latest_per_avid_returns_one_row_per_avid(advisory_factory, django_assert_num_queries):
    advisory_factory(advisory_id="A", summary="old advisory")
    latest_a = advisory_factory(advisory_id="A", summary="new advisory")

    latest_b = advisory_factory(advisory_id="B", summary="new advisory")

    with django_assert_num_queries(1):
        qs = AdvisoryV2.objects.latest_per_avid()
        results = list(qs)

    assert len(results) == 2
    ids = {obj.id for obj in results}
    assert ids == {latest_a.id, latest_b.id}


@pytest.mark.django_db
def test_latest_per_avid_excludes_older_versions(advisory_factory):
    avid = "source/C"

    older = advisory_factory(advisory_id="C", summary="old advisory")
    latest = advisory_factory(advisory_id="C", summary="new advisory")

    results = list(AdvisoryV2.objects.latest_per_avid())

    assert latest in results
    assert older not in results


@pytest.mark.django_db
def test_latest_for_avids_filters_and_collapses_correctly(
    advisory_factory, django_assert_num_queries
):

    advisory_factory(advisory_id="A", summary="old advisory")
    latest_a = advisory_factory(advisory_id="A", summary="new advisory")

    advisory_factory(advisory_id="B", summary="old advisory")
    latest_b = advisory_factory(advisory_id="B", summary="new advisory")

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
