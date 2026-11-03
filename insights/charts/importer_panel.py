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
from django.db.models import Exists
from django.db.models import OuterRef
from django.db.models import Q

from insights.models import ImporterInsight
from vulnerabilities.models import AdvisoryExploit
from vulnerabilities.models import AdvisoryV2

# Ignore Phantom Importers that don't collect Affected Packages
IGNORED_IMPORTERS = {
    "epss_importer_v2",
    "epss",
    "vulnrichment_importer_v2",
    "suse_importer_v2",
    "suse_score",
}


def packages_queryset():
    """Return a query set of package statistics by importer."""
    return (
        AdvisoryV2.objects.filter(is_latest=True)
        .exclude(datasource_id__in=IGNORED_IMPORTERS)
        .values("datasource_id")
        .annotate(
            total_advisories=Count("avid", distinct=True),
            advisories_with_packages=Count(
                "avid", filter=Q(impacted_packages__affecting_packages__isnull=False), distinct=True
            ),
            advisories_with_ghost_packages=Count(
                "avid",
                filter=Q(impacted_packages__affecting_packages__is_ghost=True),
                distinct=True,
            ),
        )
        .order_by("-total_advisories")
        .iterator()
    )


def exploits_queryset():
    """Return a query set of exploit statistics by importer."""
    kev_exploits = AdvisoryExploit.objects.filter(advisory=OuterRef("pk"), data_source="KEV")
    metasploit_exploits = AdvisoryExploit.objects.filter(
        advisory=OuterRef("pk"), data_source="Metasploit"
    )
    exploitdb_exploits = AdvisoryExploit.objects.filter(
        advisory=OuterRef("pk"), data_source="Exploit-DB"
    )

    return (
        AdvisoryV2.objects.filter(is_latest=True)
        .exclude(datasource_id__in=IGNORED_IMPORTERS)
        .annotate(
            has_kev=Exists(kev_exploits),
            has_metasploit=Exists(metasploit_exploits),
            has_exploitdb=Exists(exploitdb_exploits),
        )
        .values("datasource_id")
        .annotate(
            advisories_with_kev=Count("avid", filter=Q(has_kev=True), distinct=True),
            advisories_with_metasploit=Count(
                "avid", filter=Q(has_kev=False, has_metasploit=True), distinct=True
            ),
            advisories_with_exploitdb=Count(
                "avid",
                filter=Q(has_kev=False, has_metasploit=False, has_exploitdb=True),
                distinct=True,
            ),
        )
        .iterator()
    )


def iter_importer_insights():
    """Yield ImporterInsight objects by merging package and exploit statistics."""
    exploit_stats_by_importer = {}
    for record in exploits_queryset():
        exploit_stats_by_importer[record["datasource_id"]] = record

    for pkg_record in packages_queryset():
        datasource_id = pkg_record["datasource_id"]
        exploit_record = exploit_stats_by_importer.get(datasource_id, {})

        yield ImporterInsight(
            importer=datasource_id,
            total_advisories=pkg_record["total_advisories"],
            advisories_with_packages=pkg_record["advisories_with_packages"],
            advisories_with_ghost_packages=pkg_record["advisories_with_ghost_packages"],
            advisories_with_kev=exploit_record.get("advisories_with_kev", 0),
            advisories_with_metasploit=exploit_record.get("advisories_with_metasploit", 0),
            advisories_with_exploitdb=exploit_record.get("advisories_with_exploitdb", 0),
        )


def collect_importers(pipeline):
    """Calculates and stores importer insights."""

    # Two charts use this function, so we avoid rerunning the query twice
    if pipeline.importer_insights:
        return

    for insight in iter_importer_insights():
        pipeline.importer_insights.append(insight)


def _get_snapshot_data(snapshot: Any, build_columns_fn) -> Dict[str, Any]:
    """Helper to format importer statistics using a provided column builder."""
    all_importers = list(snapshot.importer_insights.order_by("-total_advisories"))
    data = {}

    if all_importers:
        # Top 5 by default for global view
        data["global"] = build_columns_fn(all_importers[:5])

        # Individual data for each importer
        for importer_insight in all_importers:
            formatted_name = importer_insight.importer
            data[formatted_name] = build_columns_fn([importer_insight])

    return data


def build_importer_package_columns(importers) -> Dict[str, Any]:
    """Helper to build mappings for Package Coverage chart as expected by Billboard.JS"""
    importer_names = []
    total_advisories = []
    advisories_with_packages = []
    advisories_without_packages = []
    advisories_with_ghost_packages = []
    advisories_without_ghost_packages = []

    for importer_insight in importers:
        importer_names.append(importer_insight.importer)
        total_advisories.append(importer_insight.total_advisories)
        advisories_with_packages.append(importer_insight.advisories_with_packages)
        advisories_without_packages.append(
            importer_insight.total_advisories - importer_insight.advisories_with_packages
        )
        advisories_with_ghost_packages.append(importer_insight.advisories_with_ghost_packages)
        advisories_without_ghost_packages.append(
            importer_insight.advisories_with_packages
            - importer_insight.advisories_with_ghost_packages
        )

    return {
        "x_categories": importer_names,
        "columns": [
            ["total_advisories"] + total_advisories,
            ["advisories_with_packages"] + advisories_with_packages,
            ["advisories_without_packages"] + advisories_without_packages,
            ["advisories_without_ghost_packages"] + advisories_without_ghost_packages,
            ["advisories_with_ghost_packages"] + advisories_with_ghost_packages,
        ],
        "groups": [
            ["advisories_with_packages", "advisories_without_packages"],
            ["advisories_without_ghost_packages", "advisories_with_ghost_packages"],
        ],
    }


def build_importer_exploit_columns(importers) -> Dict[str, Any]:
    """Helper to build mappings for Exploit Coverage chart as expected by Billboard.JS"""
    importer_names = []
    total_advisories = []
    advisories_with_exploits = []
    advisories_without_exploits = []
    advisories_with_kev = []
    advisories_with_metasploit = []
    advisories_with_exploitdb = []

    for importer_insight in importers:
        importer_names.append(importer_insight.importer)
        total_advisories.append(importer_insight.total_advisories)
        advisories_with_kev.append(importer_insight.advisories_with_kev)
        advisories_with_metasploit.append(importer_insight.advisories_with_metasploit)
        advisories_with_exploitdb.append(importer_insight.advisories_with_exploitdb)

        total_with_exploits = (
            importer_insight.advisories_with_kev
            + importer_insight.advisories_with_metasploit
            + importer_insight.advisories_with_exploitdb
        )
        advisories_with_exploits.append(total_with_exploits)
        advisories_without_exploits.append(importer_insight.total_advisories - total_with_exploits)

    return {
        "x_categories": importer_names,
        "columns": [
            ["total_advisories"] + total_advisories,
            ["advisories_with_exploits"] + advisories_with_exploits,
            ["advisories_without_exploits"] + advisories_without_exploits,
            ["advisories_with_exploitdb"] + advisories_with_exploitdb,
            ["advisories_with_metasploit"] + advisories_with_metasploit,
            ["advisories_with_kev"] + advisories_with_kev,
        ],
        "groups": [
            ["advisories_with_exploits", "advisories_without_exploits"],
            ["advisories_with_exploitdb", "advisories_with_metasploit", "advisories_with_kev"],
        ],
    }
