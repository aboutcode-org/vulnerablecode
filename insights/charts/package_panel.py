#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from collections import Counter
from collections import defaultdict
from typing import Any
from typing import Dict

from django.db.models import Count
from django.db.models import F
from django.db.models import Q

from insights.models import PackageCWEInsight
from insights.models import PackageInsight
from insights.models import PackageNameInsight
from insights.utils import get_cwe_label
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2

# Generic OWASP category CWEs used by NVD, not actual weakness IDs.
IGNORED_CWE_IDS = [937, 1035]


# Package Distribution
def ecosystem_distribution_queryset(package_types):
    """Return a query set of total package counts per ecosystem."""
    return (
        PackageV2.objects.filter(type__in=package_types)
        .values("type")
        .annotate(total_package_count=Count("id"))
        .iterator()
    )


def iter_ecosystem_distribution_insights(package_types):
    """Yield total package type counts per ecosystem."""
    for package_stat in ecosystem_distribution_queryset(package_types):
        yield package_stat["type"], package_stat["total_package_count"]


def collect_ecosystem_distribution(pipeline: Any) -> None:
    """Collect total package type counts per ecosystem."""
    for package_type, total_packages in iter_ecosystem_distribution_insights(pipeline.packages):
        if package_type in pipeline.package_insights:
            pipeline.package_insights[package_type].total_packages = total_packages


def format_ecosystem_distribution(snapshot: Any) -> Dict[str, Any]:
    """Format the Ecosystem Distribution Chart as expected by Billboard.JS"""
    stats = list(snapshot.package_insights.exclude(package="global").order_by("-total_packages"))

    columns = [[stat.package, stat.total_packages] for stat in stats[:10]]

    others_count = sum(stat.total_packages for stat in stats[10:])
    others_list = [[stat.package, stat.total_packages] for stat in stats[10:20]]
    if others_count > 0:
        columns.append(["Others", others_count])

    return {"global": {"columns": columns, "others_list": others_list}}


# Top 10 Packages
def top_packages_queryset(package_type: str):
    """Return a query set of the top 10 packages by number of distinct advisories."""
    return (
        PackageV2.objects.filter(type=package_type)
        .values("name")
        .annotate(
            count=Count(
                "affected_in_impacts__advisory",
                filter=Q(affected_in_impacts__advisory__is_latest=True),
            )
        )
        .filter(count__gt=0)
        .order_by("-count")[:10]
        .iterator()
    )


def iter_packages_insights(package_type: str, insight_obj: Any):
    """Yield PackageNameInsight objects for the top 10 packages of a given type."""
    for stat in top_packages_queryset(package_type):
        yield PackageNameInsight(
            package_insight=insight_obj, name=stat["name"], count=stat["count"]
        )


def collect_packages(pipeline: Any, package_type: str) -> None:
    """Collect the top 10 packages for a package type"""
    insight_obj = pipeline.package_insights[package_type]
    for insight in iter_packages_insights(package_type, insight_obj):
        pipeline.package_names.append(insight)


def build_name_chart_columns(name_counts: dict) -> Dict[str, Any]:
    """Helper to build package name donut charts."""
    return {"columns": [[name, count] for name, count in name_counts.items()]}


def format_top_packages(snapshot: Any) -> Dict[str, Any]:
    """
    Format name data for the frontend donut chart as expected by Billboard.JS
    Returns Top 10 package names for each package type and global.
    """
    data = {}
    global_counts = defaultdict(int)

    for package_insight in (
        snapshot.package_insights.exclude(package="global").prefetch_related("names").all()
    ):
        name_counts = {ns.name: ns.count for ns in package_insight.names.all()}
        data[package_insight.package] = build_name_chart_columns(name_counts)
        for name, count in name_counts.items():
            global_counts[name] += count

    top_global = dict(Counter(global_counts).most_common(10))
    data["global"] = build_name_chart_columns(top_global)
    return data


# Top CWE Distribution
def compute_top_cwes(packages=None) -> dict:
    """Computes the top 10 CWEs for the given queryset of packages. If None, computes globally."""
    qs = AdvisoryV2.objects.filter(weaknesses__isnull=False)
    if packages is not None:
        qs = qs.filter(impacted_packages__affecting_packages__in=packages)

    top_10 = (
        qs.values(cwe=F("weaknesses__cwe_id"))
        .exclude(cwe__in=IGNORED_CWE_IDS)
        .annotate(count=Count("avid", distinct=True))
        .order_by("-count")[:10]
    )
    return {stat["cwe"]: stat["count"] for stat in top_10 if stat["cwe"]}


def iter_cwes_insights(insight_obj: Any):
    """Yield PackageCWEInsight objects for the global top 10 CWE distribution."""
    for cwe_id, count in compute_top_cwes().items():
        yield PackageCWEInsight(package_insight=insight_obj, cwe_id=cwe_id, count=count)


def collect_cwes(pipeline: Any) -> None:
    """Collect the global top 10 CWE distribution."""
    if "global" not in pipeline.package_insights:
        pipeline.package_insights["global"] = PackageInsight(package="global")

    # Collect top 10 CWEs globally
    insight_obj = pipeline.package_insights["global"]
    for insight in iter_cwes_insights(insight_obj):
        pipeline.package_cwes.append(insight)


def build_cwe_chart_columns(cwe_counts: dict) -> Dict[str, Any]:
    """Helper to CWE chart as expected by Billboard.JS"""
    # Sort CWEs by count in descending order
    sorted_cwes = sorted(cwe_counts.items(), key=lambda item: item[1], reverse=True)
    return {
        "columns": [
            ["x"] + [cwe_id for cwe_id, count in sorted_cwes],
            ["Advisories"] + [count for cwe_id, count in sorted_cwes],
        ],
        "full_labels": [get_cwe_label(cwe_id) for cwe_id, count in sorted_cwes],
    }


def format_top_cwes(snapshot: Any) -> Dict[str, Any]:
    """Format CWE distribution data."""
    data = {}
    try:
        global_insight = snapshot.package_insights.get(package="global")
        cwe_counts = {cwe.cwe_id: cwe.count for cwe in global_insight.cwes.all()}
        if cwe_counts:
            data["global"] = build_cwe_chart_columns(cwe_counts)
    except PackageInsight.DoesNotExist:
        pass

    return data
