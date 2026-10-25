# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from datetime import timedelta

from django.utils import timezone

from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import LoopProgress
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerablecode.settings import (
    VULNERABLECODE_MINIMUM_PIPELINE_RUNS_TO_RETAIN as minimum_number_of_runs_to_keep,
)
from vulnerablecode.settings import VULNERABLECODE_PIPELINE_RUN_RETENTION_DAYS as retention_days


class CleanupPipelineRuns(VulnerableCodePipeline):
    """Remove pipeline runs older than the retention period while preserving the configured minimum number of runs."""

    pipeline_id = "cleanup_pipeline_runs"

    run_interval = 1440
    run_priority = PipelineSchedule.ExecutionPriority.DEFAULT

    @classmethod
    def steps(cls):
        return (cls.cleanup_old_pipeline_runs,)

    def cleanup_old_pipeline_runs(self):
        """Remove pipeline runs older than the retention period while preserving the configured minimum number of runs."""

        pipelines = PipelineSchedule.objects.all()
        pipeline_count = 0
        deleted_run_count = 0

        progress = LoopProgress(
            total_iterations=pipelines.count(), progress_step=5, logger=self.log
        )
        for pipeline in progress.iter(pipelines):
            cutoff = timezone.now() - timedelta(days=retention_days)
            keep_ids = list(
                pipeline.pipelineruns.filter(run_exitcode__isnull=False)
                .order_by("-created_date")[:minimum_number_of_runs_to_keep]
                .values_list("run_id", flat=True)
            )
            runs_to_delete = pipeline.pipelineruns.filter(created_date__lt=cutoff).exclude(
                run_id__in=keep_ids
            )

            if runs_to_delete.exists():
                pipeline_count += 1

            while runs_to_delete.exists():
                chunk_ids = list(runs_to_delete[:5000].values_list("run_id", flat=True))
                if not chunk_ids:
                    break

                count, _ = pipeline.pipelineruns.filter(run_id__in=chunk_ids).delete()
                deleted_run_count += count

        self.log(
            f"Successfully removed {deleted_run_count:,d} runs from {pipeline_count} pipelines that were older than {retention_days} days."
        )
