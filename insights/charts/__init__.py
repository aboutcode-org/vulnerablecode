#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from functools import partial

from insights.models import ChartDefinition

from .data_quality_panel import collect_data_quality_todos_resolutions
from .data_quality_panel import collect_open_issues_to_datasource
from .data_quality_panel import format_issue_contribution_donut
from .data_quality_panel import format_issue_type_bar
from .data_quality_panel import format_todos_resolution_timeline
from .importer_panel import _get_snapshot_data
from .importer_panel import build_importer_exploit_columns
from .importer_panel import build_importer_package_columns
from .importer_panel import collect_importers
from .overview_panel import collect_kpi_card
from .overview_panel import collect_yearly_distribution
from .overview_panel import format_coverage_comparison
from .overview_panel import format_growth_trend
from .overview_panel import format_kpi_card
from .overview_panel import format_yearly_distribution
from .package_panel import collect_cwes
from .package_panel import collect_ecosystem_distribution
from .package_panel import collect_packages
from .package_panel import format_ecosystem_distribution
from .package_panel import format_top_cwes
from .package_panel import format_top_packages
from .severity_panel import collect_severities
from .severity_panel import get_severity_snapshot_data

CHARTS = [
    ChartDefinition(
        id="overview-stats",
        title="Overview Stats",
        panel="overview_panel",
        chart_type="custom",
        formatter_fn=format_kpi_card,
        collect_fn=collect_kpi_card,
    ),
    ChartDefinition(
        id="overview-cross-validation",
        title="Coverage Comparison",
        panel="overview_panel",
        chart_type="stacked_bar",
        formatter_fn=format_coverage_comparison,
        collect_fn=collect_importers,
    ),
    ChartDefinition(
        id="overview-growth-trend",
        title="Advisories Imported in the last 30 days",
        panel="overview_panel",
        chart_type="colored_bar",
        formatter_fn=format_growth_trend,
        collect_fn=collect_kpi_card,
    ),
    ChartDefinition(
        id="overview-historical",
        title="Advisories Published in the Last 10 years",
        panel="overview_panel",
        chart_type="colored_bar",
        formatter_fn=format_yearly_distribution,
        collect_fn=collect_yearly_distribution,
    ),
    ChartDefinition(
        id="pkg-dist-donut",
        title="Ecosystem Distribution",
        panel="package_panel",
        chart_type="donut",
        formatter_fn=format_ecosystem_distribution,
        collect_fn=collect_ecosystem_distribution,
    ),
    ChartDefinition(
        id="pkg-name-bar",
        title="Top 10 Packages",
        panel="package_panel",
        chart_type="colored_bar",
        formatter_fn=format_top_packages,
        collect_fn=collect_packages,
        is_per_package=True,
    ),
    ChartDefinition(
        id="pkg-cwe-bar",
        title="Top 10 CWE Distribution",
        panel="package_panel",
        chart_type="colored_bar",
        formatter_fn=format_top_cwes,
        collect_fn=collect_cwes,
        is_per_package=False,
        has_search=True,
    ),
    ChartDefinition(
        id="severity-scatter-plot",
        title="Severity Distribution across Packages",
        panel="severity_panel",
        chart_type="scatter",
        formatter_fn=get_severity_snapshot_data,
        collect_fn=collect_severities,
        has_search=True,
    ),
    ChartDefinition(
        id="importer-empty-pkg-bar",
        title="PURL Coverage across Importers",
        panel="importer_panel",
        chart_type="importer_bar",
        formatter_fn=partial(_get_snapshot_data, build_columns_fn=build_importer_package_columns),
        collect_fn=collect_importers,
    ),
    ChartDefinition(
        id="importer-exploit-bar",
        title="Exploit Coverage across Importers",
        panel="importer_panel",
        chart_type="importer_bar",
        formatter_fn=partial(_get_snapshot_data, build_columns_fn=build_importer_exploit_columns),
        collect_fn=collect_importers,
    ),
    ChartDefinition(
        id="dq-issue-type-bar",
        title="Open Issues by Type per Datasource",
        panel="data_quality_panel",
        chart_type="colored_bar",
        formatter_fn=format_issue_type_bar,
        collect_fn=collect_open_issues_to_datasource,
    ),
    ChartDefinition(
        id="dq-importer-contribution-donut",
        title="Datasource Contribution per Open Issue",
        panel="data_quality_panel",
        chart_type="donut",
        formatter_fn=format_issue_contribution_donut,
    ),
    ChartDefinition(
        id="dq-resolution-timeline",
        title="Issue Opened and Resolved Monthly",
        panel="data_quality_panel",
        chart_type="line",
        formatter_fn=format_todos_resolution_timeline,
        collect_fn=collect_data_quality_todos_resolutions,
    ),
]

PANELS = [
    "overview_panel",
    "package_panel",
    "severity_panel",
    "importer_panel",
    "data_quality_panel",
]
PANEL_LABELS = {
    "overview_panel": "Overview",
    "package_panel": "Package Analytics",
    "severity_panel": "Severity Analytics",
    "importer_panel": "Importer Analytics",
    "data_quality_panel": "Data Quality Analytics",
}
PANEL_LAYOUTS = {
    "package_panel": "split_top",
}
