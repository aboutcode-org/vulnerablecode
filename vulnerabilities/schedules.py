#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import logging

import django_rq
from redis.exceptions import ConnectionError

from vulnerabilities.tasks import enqueue_pipeline
from vulnerablecode.settings import VULNERABLECODE_PIPELINE_TIMEOUT

log = logging.getLogger(__name__)
scheduler = django_rq.get_scheduler()


def schedule_execution(pipeline_schedule, execute_now=False):
    """
    Takes a `PackageSchedule` object as input and schedule a
    recurring job using `rq_scheduler` to execute the pipeline.
    """
    first_execution = datetime.datetime.now(tz=datetime.timezone.utc)
    if not execute_now:
        first_execution = pipeline_schedule.next_run_date

    interval_in_seconds = pipeline_schedule.run_interval * 24 * 60 * 60

    job = scheduler.schedule(
        scheduled_time=first_execution,
        func=enqueue_pipeline,
        args=[pipeline_schedule.pipeline_id],
        interval=interval_in_seconds,
        result_ttl=f"{VULNERABLECODE_PIPELINE_TIMEOUT}h",
        repeat=None,
    )
    return job._id


def scheduled_job_exists(job_id):
    """
    Check if a scheduled job with the given job ID exists.
    """
    return job_id and (job_id in scheduler)


def clear_job(job):
    """
    Take a job object or job ID as input
    and cancel the corresponding scheduled job.
    """
    return scheduler.cancel(job)


def clear_zombie_pipeline_schedules(logger=log):
    """
    Clear scheduled jobs not associated with any PackageSchedule object.
    """
    from vulnerabilities.models import PipelineSchedule

    schedule_ids = PipelineSchedule.objects.all().values_list("schedule_work_id", flat=True)

    for job in scheduler.get_jobs():
        if job._id not in schedule_ids:
            logger.info(f"Deleting scheduled job {job}")
            clear_job(job)


def is_redis_running(logger=log):
    """
    Check the status of the Redis server.
    """
    try:
        connection = django_rq.get_connection()
        return connection.ping()
    except ConnectionError as e:
        error_message = f"Error checking Redis status: {e}. Redis is not reachable."
        logger.error(error_message)
        return False


def update_pipeline_schedule():
    """Create schedules for new pipelines and delete schedules for removed pipelines."""

    from vulnerabilities.importers import IMPORTERS_REGISTRY
    from vulnerabilities.improvers import IMPROVERS_REGISTRY
    from vulnerabilities.models import PipelineSchedule

    pipeline_ids = [*IMPORTERS_REGISTRY.keys(), *IMPROVERS_REGISTRY.keys()]

    PipelineSchedule.objects.exclude(pipeline_id__in=pipeline_ids).delete()
    [PipelineSchedule.objects.get_or_create(pipeline_id=id) for id in pipeline_ids]
