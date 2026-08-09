from functools import partial

from insights.models import ChartDefinition

from .importer_panel import _get_snapshot_data
from .importer_panel import build_importer_exploit_columns
from .importer_panel import build_importer_package_columns
from .importer_panel import collect_importers
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
