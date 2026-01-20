#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from unittest import mock

from django.test import TestCase

from vulnerabilities.models import PipelineRun
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.tasks import execute_pipeline


class OneTimePipeline(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "one_time_pipeline_test"
    run_once = True

    def collect_advisories(self):
        return []

    def advisories_count(self):
        return 0


class NotOneTimePipeline(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "not_one_time_pipeline_test"
    run_once = False

    def collect_advisories(self):
        return []

    def advisories_count(self):
        return 0


class TestOneTimePipelineExecution(TestCase):
    @mock.patch("vulnerabilities.models.PipelineSchedule.create_new_job")
    @mock.patch(
        "vulnerabilities.models.PipelineSchedule.pipeline_class",
        new_callable=mock.PropertyMock,
    )
    def test_onetime_pipeline_deactivation(self, mock_pipeline_class, mock_create_job):
        mock_create_job.return_value = True
        mock_pipeline_class.return_value = OneTimePipeline

        ps, _ = PipelineSchedule.objects.get_or_create(
            pipeline_id=OneTimePipeline.pipeline_id,
            defaults={
                "is_run_once": OneTimePipeline.run_once,
            },
        )

        self.assertTrue(ps.is_run_once)
        self.assertTrue(ps.is_active)

        run = PipelineRun.objects.create(
            pipeline=ps,
        )
        execute_pipeline(ps.pipeline_id, run.run_id)

        ps.refresh_from_db()
        self.assertTrue(ps.is_run_once)
        self.assertFalse(ps.is_active)

    @mock.patch("vulnerabilities.models.PipelineSchedule.create_new_job")
    @mock.patch(
        "vulnerabilities.models.PipelineSchedule.pipeline_class",
        new_callable=mock.PropertyMock,
    )
    def test_normal_pipeline_no_deactivation(self, mock_pipeline_class, mock_create_job):
        mock_create_job.return_value = True
        mock_pipeline_class.return_value = NotOneTimePipeline

        ps, _ = PipelineSchedule.objects.get_or_create(
            pipeline_id=NotOneTimePipeline.pipeline_id,
            defaults={
                "is_run_once": NotOneTimePipeline.run_once,
            },
        )

        self.assertFalse(ps.is_run_once)
        self.assertTrue(ps.is_active)

        run = PipelineRun.objects.create(
            pipeline=ps,
        )
        execute_pipeline(ps.pipeline_id, run.run_id)

        ps.refresh_from_db()
        self.assertFalse(ps.is_run_once)
        self.assertTrue(ps.is_active)
