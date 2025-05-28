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
    """Initialize schedule jobs for active PipelineSchedule."""
    active_pipeline_qs = models.PipelineSchedule.objects.filter(is_active=True).order_by(
        "created_date"
    )
    for pipeline_schedule in active_pipeline_qs:
        if scheduled_job_exists(pipeline_schedule.schedule_work_id):
            continue
        new_id = pipeline_schedule.create_new_job()
        pipeline_schedule.schedule_work_id = new_id
        pipeline_schedule.save(update_fields=["schedule_work_id"])


class Command(rqscheduler.Command):
    def handle(self, *args, **kwargs):
        clear_zombie_pipeline_schedules()
        update_pipeline_schedule()
        init_pipeline_scheduled()
        super(Command, self).handle(*args, **kwargs)
