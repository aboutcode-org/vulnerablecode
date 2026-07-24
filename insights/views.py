#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from django.db.models import Count
from django.shortcuts import redirect
from django.shortcuts import render

from insights.charts import CHARTS
from insights.charts import PANEL_LABELS
from insights.charts import PANEL_LAYOUTS
from insights.charts import PANELS
from insights.charts.package_panel import build_cwe_chart_columns
from insights.charts.package_panel import compute_top_cwes
from insights.charts.severity_panel import aggregate_severity_buckets
from insights.charts.severity_panel import format_severity_chart_data
from insights.models import DailySnapshot
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2


def _severity_search(search_query):
    """Executes a severity search for a given PUrl"""
    packages = PackageV2.objects.search(search_query)
    error = None

    if packages.exists():
        severities = (
            AdvisoryV2.objects.filter(
                impacted_packages__affecting_packages__in=packages,
                severities__isnull=False,
                severities__scoring_system__icontains="cvss",
            )
            .values("severities__value")
            .annotate(sev_count=Count("id", distinct=True))
        )
        buckets = aggregate_severity_buckets(severities, "sev_count")
    else:
        buckets = [0] * 10
        error = "No data available for this query."

    return format_severity_chart_data(buckets), error


def _cwe_search(search_query):
    """Executes a CWE search for a given PUrl"""
    packages = PackageV2.objects.search(search_query)
    error = None

    if packages.exists():
        cwe_counts = compute_top_cwes(packages)
        chart_data = build_cwe_chart_columns(cwe_counts)
    else:
        chart_data = {}
        error = "No packages found for this query."

    return {"pkg-cwe-bar": chart_data}, error


def insights_dashboard(request, panel_id=None):
    """Dashboard view to display insights."""

    if not panel_id or panel_id not in PANELS:
        return redirect("insights-panel", panel_id=PANELS[0])

    panels = []
    for panel_key in PANELS:
        panel_charts = [chart for chart in CHARTS if chart.panel == panel_key]
        panels.append(
            {
                "id": panel_key,
                "label": PANEL_LABELS[panel_key],
                "layout": PANEL_LAYOUTS.get(panel_key, "standard"),
                "charts": panel_charts,
            }
        )

    try:
        snapshot = DailySnapshot.objects.latest()
        last_time = snapshot.created_at

        snapshot_data = {}
        for chart_def in CHARTS:
            if chart_def.formatter_fn:
                snapshot_data[chart_def.id] = chart_def.formatter_fn(snapshot)
    except DailySnapshot.DoesNotExist:
        last_time = None
        snapshot_data = {}

    search_query = request.GET.get("q", "").strip()
    search_results_dict = None
    search_error = None

    if search_query:
        if panel_id == "severity_panel":
            search_results_dict, search_error = _severity_search(search_query)
        elif panel_id == "package_panel":
            search_results_dict, search_error = _cwe_search(search_query)

    context = {
        "panels": panels,
        "current_panel_id": panel_id,
        "last_snapshot_time": last_time,
        "snapshot_dict": {"snapshot_data": snapshot_data},
        "search_query": search_query,
        "search_results_dict": search_results_dict,
        "search_error": search_error,
    }
    return render(request, "insights/dashboard.html", context)
