#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from aboutcode.pipeline import LoopProgress
from django.db import transaction

from insights.graphs import GRAPHS
from insights.models import DailySnapshot
from insights.models import ImporterInsight
from insights.models import PackageCWEInsight
from insights.models import PackageInsight
from insights.models import PackageNameInsight
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline


class InsightsSnapshotPipeline(VulnerableCodePipeline):
    """Pipeline to compute aggregated statistics for the Insights Dashboard."""

    pipeline_id = "insights_snapshot"

    @classmethod
    def steps(cls):
        return (
            cls.compute_graph_analytics,
            cls.save_snapshot,
        )

    def compute_graph_analytics(self):
        """Run graph collect_fns to compute analytics."""

        # List all package types
        self.packages = list(PackageV2.objects.order_by().values_list("type", flat=True).distinct())

        self.package_insights = {pkg: PackageInsight(package=pkg) for pkg in self.packages}
        self.package_names = []
        self.package_cwes = []
        self.importer_insights = []
        self.severity_insight = None

        active_graphs = {
            graph_id: graph_def for graph_id, graph_def in GRAPHS.items() if graph_def.collect_fn
        }

        # Count steps for progress bar
        total_steps = sum(
            len(self.packages) if graph_def.is_per_package else 1
            for graph_def in active_graphs.values()
        )

        progress = LoopProgress(total_iterations=total_steps, logger=self.log, progress_step=1)
        progress_iter = iter(progress.iter(range(total_steps)))

        for graph_id, graph_def in active_graphs.items():
            self.log(f"Running collect_fn for {graph_id}")

            if graph_def.is_per_package:
                for pkg in self.packages:
                    next(progress_iter, None)
                    graph_def.collect_fn(self, pkg)
            else:
                next(progress_iter, None)
                graph_def.collect_fn(self)

    @transaction.atomic
    def save_snapshot(self):
        self.log("Saving snapshot")
        snapshot = DailySnapshot.objects.create()

        for insight in self.package_insights.values():
            insight.snapshot = snapshot

        for insight in self.importer_insights:
            insight.snapshot = snapshot

        if self.severity_insight:
            self.severity_insight.snapshot = snapshot
            self.severity_insight.save()

        PackageInsight.objects.bulk_create(self.package_insights.values(), batch_size=5000)
        PackageNameInsight.objects.bulk_create(self.package_names, batch_size=5000)
        PackageCWEInsight.objects.bulk_create(self.package_cwes, batch_size=5000)
        ImporterInsight.objects.bulk_create(self.importer_insights, batch_size=5000)

        self.log("Snapshot saved successfully.")
