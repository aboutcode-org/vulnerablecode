#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from typing import Any
from typing import Dict

from django.db.models import Count

from insights.models import SeverityInsight
from vulnerabilities.models import AdvisoryV2

CVSS_SCORE_LABELS = ["0-1", "1-2", "2-3", "3-4", "4-5", "5-6", "6-7", "7-8", "8-9", "9-10"]


def aggregate_severity_buckets(queryset: Any, count_field: str) -> list[int]:
    """Helper to aggregate a queryset of severity values into exactly 10 CVSS buckets."""
    buckets = [0] * 10

    for severity in queryset:
        try:
            score = float(severity.get("severities__value"))
            if 0 <= score <= 10:
                buckets[min(9, int(score))] += severity[count_field]
        except (ValueError, TypeError):
            continue

    return buckets


def iter_severity_insights():
    """Yield SeverityInsight objects."""
    advisory_severities = (
        AdvisoryV2.objects.filter(
            severities__isnull=False, severities__scoring_system__icontains="cvss"
        )
        .values("severities__value")
        .annotate(advisory_count=Count("avid", distinct=True))
        .iterator()
    )

    severity_buckets = aggregate_severity_buckets(advisory_severities, "advisory_count")
    yield SeverityInsight(buckets=severity_buckets)


def collect_severities(pipeline: Any) -> None:
    """Pre-compute the global severity distribution."""
    for insight in iter_severity_insights():
        pipeline.severity_insight = insight


def format_severity_chart_data(buckets: list[int]) -> Dict[str, Any]:
    """Helper to build mappings for Severity Distribution chart as expected by Billboard.JS"""
    return {
        "columns": [
            ["x"] + CVSS_SCORE_LABELS,
            ["Advisories"] + buckets,
        ]
    }


def get_severity_snapshot_data(snapshot: Any) -> Dict[str, Any]:
    """Return the global severity distribution for the frontend scatter plot."""
    if hasattr(snapshot, "severity_insight"):
        insight = snapshot.severity_insight
        global_buckets = insight.buckets
    else:
        global_buckets = [0] * 10

    return {"global": format_severity_chart_data(global_buckets)}
