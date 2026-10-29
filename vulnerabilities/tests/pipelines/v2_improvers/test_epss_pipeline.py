#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from unittest import mock

import pytest
from django.utils import timezone

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import EPSSScore
from vulnerabilities.pipelines.v2_improvers.epss_pipeline import EPSSPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).resolve().parent.parent.parent / "test_data" / "epss"


@pytest.mark.django_db
@mock.patch("urllib.request.urlopen")
def test_epss_pipeline(mock_urlopen):
    test_file = TEST_DATA / "epss_scores_current.csv.gz"
    with open(test_file, "rb") as f:
        mock_urlopen.return_value = f
        pipeline = EPSSPipeline()
        pipeline.execute()

    results = [
        {
            "cve": score.alias.alias,
            "date": score.date.isoformat(),
            "is_latest": score.is_latest,
            "percentile": f"{score.percentile:.5f}",
            "score": f"{score.score:.5f}",
        }
        for score in EPSSScore.objects.select_related("alias").order_by("alias__alias")
    ]
    expected_file = TEST_DATA / "epss_scores_expected.json"
    util_tests.check_results_against_json(results, expected_file)


@pytest.mark.django_db
def test_epss_pipeline_prune_old_scores():
    alias = AdvisoryAlias.objects.create(alias="CVE-2021-25665")
    today = timezone.now().date()

    recent = EPSSScore.objects.create(
        alias=alias,
        date=today - timedelta(days=30),
        score=Decimal("0.00405"),
        percentile=Decimal("0.61137"),
        is_latest=True,
    )
    old = EPSSScore.objects.create(
        alias=alias,
        date=today - timedelta(days=95),
        score=Decimal("0.00300"),
        percentile=Decimal("0.50000"),
        is_latest=False,
    )

    EPSSPipeline().prune_old_scores()

    assert EPSSScore.objects.filter(id=recent.id).exists()
    assert not EPSSScore.objects.filter(id=old.id).exists()
