#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from vulnerabilities import models
from vulnerabilities.pipelines.management.cleanup_pipeline_runs import CleanupPipelineRuns
from vulnerabilities.tests.pipelines import TestLogger


class TestCleanupPipelineRuns(TestCase):
    def setUp(self):
        self.logger = TestLogger()

        self.schedule1 = models.PipelineSchedule.objects.create(pipeline_id="test_pipeline")
        for _ in range(70):
            models.PipelineRun.objects.create(
                pipeline=self.schedule1,
                run_exitcode=0,
            )

    def test_pipelines_management_cleanup_pipeline_runs_with_old_and_new_runs(self):
        cutoff = timezone.now() - timedelta(days=100)
        old_run_ids = models.PipelineRun.objects.all()[:60].values("run_id")
        models.PipelineRun.objects.filter(run_id__in=old_run_ids).update(created_date=cutoff)

        self.assertEqual(models.PipelineRun.objects.count(), 70)
        pipeline = CleanupPipelineRuns()
        pipeline.log = self.logger.write
        exit_code, _ = pipeline.execute()

        self.assertEqual(exit_code, 0)
        self.assertEqual(models.PipelineRun.objects.count(), 60)
        self.assertIn(
            "Successfully removed 10 runs from 1 pipelines that were older than 60 days",
            self.logger.getvalue(),
        )

    def test_pipelines_management_cleanup_pipeline_runs_with_new_runs_only(self):
        self.assertEqual(models.PipelineRun.objects.count(), 70)
        pipeline = CleanupPipelineRuns()
        pipeline.log = self.logger.write
        exit_code, _ = pipeline.execute()

        self.assertEqual(exit_code, 0)
        self.assertEqual(models.PipelineRun.objects.count(), 70)
        self.assertIn(
            "Successfully removed 0 runs from 0 pipelines that were older than 60 days",
            self.logger.getvalue(),
        )
