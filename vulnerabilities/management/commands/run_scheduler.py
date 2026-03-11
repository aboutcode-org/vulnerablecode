#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from django_rq.management.commands import rqscheduler

from vulnerabilities import models
from vulnerabilities.schedules import clear_zombie_pipeline_schedules
from vulnerabilities.schedules import scheduled_job_exists
from vulnerabilities.schedules import update_pipeline_schedule


def init_pipeline_scheduled():
    """
    Initialize schedule jobs for active PipelineSchedule.
        - Create new schedule if there is no schedule for active pipeline
        - Create new schedule if schedule is corrupted for an active pipeline
        - Delete schedule for inactive pipeline
    """
    pipeline_qs = models.PipelineSchedule.objects.order_by("created_date")
    for pipeline in pipeline_qs:
        reset_schedule = pipeline.is_active != bool(pipeline.schedule_work_id)
        if not scheduled_job_exists(pipeline.schedule_work_id):
            reset_schedule = True

        if reset_schedule:
            pipeline.schedule_work_id = pipeline.create_new_job()
            pipeline.save(update_fields=["schedule_work_id"])


class Command(rqscheduler.Command):
    def handle(self, *args, **kwargs):
        clear_zombie_pipeline_schedules()
        update_pipeline_schedule()
        init_pipeline_scheduled()
        super(Command, self).handle(*args, **kwargs)
