#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import logging
from collections import Counter
from contextlib import suppress
from io import StringIO
from traceback import format_exc as traceback_format_exc

import django_rq
from redis.exceptions import ConnectionError
from rq import Worker

from vulnerabilities import models
from vulnerablecode.settings import RQ_QUEUES

logger = logging.getLogger(__name__)

queues = {queue: django_rq.get_queue(queue) for queue in RQ_QUEUES.keys()}


def execute_pipeline(pipeline_id, run_id):
    from vulnerabilities.pipelines import VulnerableCodePipeline

    logger.info(f"Enter `execute_pipeline` {pipeline_id}")

    run = models.PipelineRun.objects.get(
        run_id=run_id,
    )
    run.set_run_started()
    run.set_vulnerablecode_version_and_commit()

    output = ""
    exitcode = 0
    run_class = run.pipeline_class
    if issubclass(run_class, VulnerableCodePipeline):
        pipeline_instance = run_class(run_instance=run)
        exitcode, output = pipeline_instance.execute()
    else:
        output = f"{pipeline_id} is not a valid importer/improver."
        exitcode = 1

    run.set_run_ended(exitcode=exitcode, output=output)

    # Onetime pipeline are inactive after first execution.
    pipeline = run.pipeline
    if pipeline.is_run_once:
        pipeline.is_active = False
        pipeline.save()

    logger.info("Update Run instance with exitcode, output, and end_date")


def set_run_failure(job, connection, type, value, traceback):
    from vulnerabilities.models import PipelineRun

    try:
        run = PipelineRun.objects.get(run_id=job.id)
    except PipelineRun.DoesNotExist:
        logger.info(f"Failed to get the run instance with job.id={job.id}")
        return

    run.set_run_ended(exitcode=1, output=f"value={value} trace={traceback}")


def enqueue_run(run):
    pipeline_schedule = run.pipeline
    queue = queues.get(pipeline_schedule.get_run_priority_display())

    job = queue.enqueue(
        execute_pipeline,
        pipeline_schedule.pipeline_id,
        run.run_id,
        job_id=str(run.run_id),
        on_failure=set_run_failure,
        job_timeout=f"{pipeline_schedule.execution_timeout}h",
    )


def enqueue_pipeline(pipeline_id):
    pipeline_schedule = models.PipelineSchedule.objects.get(pipeline_id=pipeline_id)

    if pipeline_schedule.status in [
        models.PipelineRun.Status.RUNNING,
        models.PipelineRun.Status.QUEUED,
    ]:
        logger.warning(
            (
                f"Cannot enqueue a new execution for {pipeline_id} "
                "until the previous one has finished."
            )
        )
        return

    run = models.PipelineRun.objects.create(
        pipeline=pipeline_schedule,
    )

    enqueue_run(run)


def dequeue_job(job_id):
    """Remove a job from queue if it hasn't been executed yet."""

    for queue in queues.values():
        if job_id in queue.jobs:
            queue.remove(job_id)


def is_job_in_queue(job_id):
    """Return whether a job exists in any queue."""

    return any(job_id in queue.jobs for queue in queues.values())


def compute_queue_load_factor():
    """
    Compute worker load per queue.

    Load factor is the ratio of the total compute required to run all active pipelines
    in a queue to the available worker capacity for that queue over a 24-hour period.
    A value greater than 1 indicates that the number of workers is insufficient to
    run all pipelines within the schedule.

    Also compute the additional workers needed to balance each queue
    """
    field = models.PipelineSchedule._meta.get_field("run_priority")
    label_to_value = {label: value for value, label in field.choices}
    total_compute_seconds_per_queue_in_24hr_cycle = {}
    worker_per_queue = {}
    load_per_queue = {}
    seconds_in_24_hr = 86400

    with suppress(ConnectionError):
        redis_conn = django_rq.get_connection()
        queue_names = [
            w.queue_names()[0] for w in Worker.all(connection=redis_conn) if w.queue_names()
        ]
        worker_per_queue = dict(Counter(queue_names))

    for queue in RQ_QUEUES.keys():
        total_compute_seconds = 0
        active_schedules = models.PipelineSchedule.objects.filter(
            is_active=True,
            run_priority=label_to_value[queue],
        )
        for schedule in active_schedules:
            if not schedule.latest_successful_run:
                continue

            runs_per_day = (24 * 60) / schedule.run_interval
            compute_seconds_per_day = schedule.latest_successful_run.runtime * runs_per_day
            total_compute_seconds += compute_seconds_per_day

        total_compute_seconds_per_queue_in_24hr_cycle[queue] = total_compute_seconds

        if queue not in worker_per_queue:
            worker_per_queue[queue] = 0

    for queue_name, worker_count in worker_per_queue.items():
        net_load_on_queue = "no_worker"
        total_compute = total_compute_seconds_per_queue_in_24hr_cycle.get(queue_name, 0)
        total_pipeline_for_queue = models.PipelineSchedule.objects.filter(
            is_active=True, run_priority=label_to_value[queue_name]
        ).count()
        if total_compute == 0:
            continue

        unit_load_on_queue = total_compute / seconds_in_24_hr

        num_of_worker_for_balanced_queue = round(unit_load_on_queue)
        addition_worker_needed = min(
            max(num_of_worker_for_balanced_queue - worker_count, 0), total_pipeline_for_queue
        )

        if worker_count > 0:
            net_load_on_queue = unit_load_on_queue / worker_count

        load_per_queue[queue_name] = {
            "load_factor": net_load_on_queue,
            "additional_worker": addition_worker_needed,
        }

    return dict(sorted(load_per_queue.items(), key=lambda x: x[0], reverse=True))
