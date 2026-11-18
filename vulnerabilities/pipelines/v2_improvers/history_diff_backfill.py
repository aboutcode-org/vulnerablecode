#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress

from vulnerabilities.importers import IMPORTERS_REGISTRY
from vulnerabilities.models import AdvisoryHistoryDiff
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import compute_advisory_v2_diff


class HistoryDiffImproverPipeline(VulnerableCodePipeline):
    """
    Pipeline to compute and store relational history snapshot diffs.
    """

    pipeline_id = "history_diff_improver_v2"

    @classmethod
    def steps(cls):
        return (cls.calculate_history_diffs,)

    def calculate_history_diffs(self):
        # Skip excluded importers
        excluded_ids = [
            cls.pipeline_id
            for cls in IMPORTERS_REGISTRY.values()
            if getattr(cls, "exclude_from_history_diff", False)
            and getattr(cls, "pipeline_id", None)
        ]
        qs = (
            AdvisoryV2.objects.exclude(pipeline_id__in=excluded_ids)
            if excluded_ids
            else AdvisoryV2.objects.all()
        )

        avids_qs = qs.filter(history_diff__isnull=True).values_list("avid", flat=True).distinct()
        avids_count = avids_qs.count()
        self.log(f"Computing history diffs for {avids_count} advisories")

        for avid in LoopProgress(
            total_iterations=avids_count, logger=self.log, progress_step=10
        ).iter(avids_qs.iterator()):
            snapshots = list(
                qs.filter(avid=avid)
                .order_by("date_collected", "unique_content_id")
                .prefetch_related(
                    "aliases",
                    "references",
                    "weaknesses",
                    "severities",
                    "patches",
                    "impacted_packages",
                )
            )

            previous_snapshot = None

            # TODO:
            # Bulk diff creation

            for snapshot in snapshots:
                if not hasattr(snapshot, "history_diff"):  # Skip already processed advisories
                    if previous_snapshot is not None:
                        compute_advisory_v2_diff(previous_snapshot, snapshot)
                    else:
                        # For the very first snapshot, we create an empty diff to mark it as processed
                        AdvisoryHistoryDiff.objects.create(
                            advisory_after=snapshot, advisory_before=None
                        )

                previous_snapshot = snapshot

        self.log("Successfully finished history diff backfill.")
