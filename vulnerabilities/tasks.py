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
from vulnerabilities.importer import Importer
from vulnerabilities.improver import Improver
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
    elif issubclass(run_class, Importer) or issubclass(run_class, Improver):
        exitcode, output = legacy_runner(run_class=run_class, run=run)
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


def legacy_runner(run_class, run):
    from vulnerabilities.import_runner import ImportRunner
    from vulnerabilities.improve_runner import ImproveRunner

    exitcode = 0
    output = ""
    pipeline_id = run.pipeline.pipeline_id

    log_stream = StringIO()
    handler = logging.StreamHandler(log_stream)
    module_name = pipeline_id.rsplit(".", 1)[0]
    logger_modules = [module_name]
    if module_name.startswith("vulnerabilities.improvers."):
        logger_modules.append("vulnerabilities.improve_runner")
    elif module_name.startswith("vulnerabilities.importers."):
        logger_modules.append("vulnerabilities.import_runner")

    loggers = []
    for name in logger_modules:
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        loggers.append(logger)

    try:
        if issubclass(run_class, Importer):
            ImportRunner(run_class).run()
            run.append_to_log(f"Successfully imported data using {pipeline_id}")
        elif issubclass(run_class, Improver):
            ImproveRunner(improver_class=run_class).run()
            run.append_to_log(f"Successfully improved data using {pipeline_id}")
    except Exception as e:
        output = (f"Failed to run {pipeline_id}: {e!r} \n {traceback_format_exc()}",)
        exitcode = 1

    run.append_to_log(log_stream.getvalue(), is_multiline=True)
    [logger.removeHandler(handler) for logger in loggers]

    return exitcode, output


def set_run_failure(job, connection, type, value, traceback):
    from vulnerabilities.models import PipelineRun

    try:
        run = PipelineRun.objects.get(run_id=job.id)
    except PipelineRun.DoesNotExist:
        logger.info(f"Failed to get the run instance with job.id={job.id}")
        return

    run.set_run_ended(exitcode=1, output=f"value={value} trace={traceback}")


def enqueue_pipeline(pipeline_id):
    pipeline_schedule = models.PipelineSchedule.objects.get(pipeline_id=pipeline_id)
    queue = queues.get(pipeline_schedule.get_run_priority_display())

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
    job = queue.enqueue(
        execute_pipeline,
        pipeline_id,
        run.run_id,
        job_id=str(run.run_id),
        on_failure=set_run_failure,
        job_timeout=f"{pipeline_schedule.execution_timeout}h",
    )


def dequeue_job(job_id):
    """Remove a job from queue if it hasn't been executed yet."""

    for queue in queues.values():
        if job_id in queue.jobs:
            queue.remove(job_id)


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
    total_compute_seconds_per_queue = {}
    worker_per_queue = {}
    load_per_queue = {}
    seconds_in_24_hr = 86400

    for queue in RQ_QUEUES.keys():
        total_compute_seconds_per_queue[queue] = sum(
            (p.latest_successful_run.runtime / (p.run_interval / 24))
            for p in models.PipelineSchedule.objects.filter(
                is_active=True, run_priority=label_to_value[queue]
            )
            if p.latest_successful_run
        )

    with suppress(ConnectionError):
        redis_conn = django_rq.get_connection()
        queue_names = [
            w.queue_names()[0] for w in Worker.all(connection=redis_conn) if w.queue_names()
        ]
        worker_per_queue = dict(Counter(queue_names))

    for queue_name, worker_count in worker_per_queue.items():
        total_compute = total_compute_seconds_per_queue.get(queue_name, 0)
        if worker_count == 0 or total_compute == 0:
            continue

        unit_load_on_queue = total_compute / seconds_in_24_hr

        num_of_worker_for_balanced_queue = round(unit_load_on_queue)
        addition_worker_needed = max(num_of_worker_for_balanced_queue - worker_count, 0)

        net_load_on_queue = unit_load_on_queue / worker_count

        load_per_queue[queue_name] = {
            "load_factor": net_load_on_queue,
            "additional_worker": addition_worker_needed,
        }

    return dict(sorted(load_per_queue.items(), key=lambda x: x[0], reverse=True))
