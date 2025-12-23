#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import logging
from io import StringIO
from traceback import format_exc as traceback_format_exc

import django_rq

from vulnerabilities import models
from vulnerabilities.importer import Importer
from vulnerabilities.improver import Improver
from vulnerablecode.settings import VULNERABLECODE_PIPELINE_TIMEOUT

logger = logging.getLogger(__name__)

default_queue = django_rq.get_queue("default")
live_queue = django_rq.get_queue("live")


def execute_pipeline(pipeline_id, run_id, inputs=None):
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
        inputs = inputs or {}
        pipeline_instance = run_class(run_instance=run, **inputs)
        exitcode, output = pipeline_instance.execute()
    elif issubclass(run_class, Importer) or issubclass(run_class, Improver):
        exitcode, output = legacy_runner(run_class=run_class, run=run)
    else:
        output = f"{pipeline_id} is not a valid importer/improver."
        exitcode = 1

    run.set_run_ended(exitcode=exitcode, output=output)
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
    job = default_queue.enqueue(
        execute_pipeline,
        pipeline_id,
        run.run_id,
        job_id=str(run.run_id),
        on_failure=set_run_failure,
        job_timeout=f"{pipeline_schedule.execution_timeout}h",
    )


def enqueue_ad_hoc_pipeline(pipeline_ids, *, inputs=None):
    """Enqueue one-off executions for the given pipeline_ids with optional inputs.

    When multiple pipeline IDs are provided, this will create a single LivePipelineRun and attach
    each created PipelineRun to it. Returns a tuple of (live_run_id, run_ids).

    If a single pipeline ID (str) is provided, it will be wrapped into a list.
    """
    inputs = inputs or {}
    # Normalize to list
    if isinstance(pipeline_ids, str):
        pipeline_ids = [pipeline_ids]

    # Create a LivePipelineRun to group these ad-hoc runs, if any inputs (such as purl) are given
    purl_val = inputs.get("purl")
    try:
        # accept PackageURL instance as well as string
        purl_str = str(purl_val) if purl_val is not None else None
    except Exception:
        purl_str = None

    live_run = models.LivePipelineRun.objects.create(purl=purl_str)

    run_ids = []
    for pipeline_id in pipeline_ids:
        try:
            pipeline_schedule = models.PipelineSchedule.objects.get(pipeline_id=pipeline_id)
        except models.PipelineSchedule.DoesNotExist:
            pipeline_schedule = models.PipelineSchedule.objects.create(
                pipeline_id=pipeline_id,
                is_active=False,
            )

        run = models.PipelineRun.objects.create(pipeline=pipeline_schedule, live_pipeline=live_run)

        # Enqueue on the dedicated live queue
        live_queue.enqueue(
            execute_pipeline,
            pipeline_id,
            run.run_id,
            inputs,
            job_id=str(run.run_id),
            on_failure=set_run_failure,
            job_timeout=f"{pipeline_schedule.execution_timeout}h",
        )
        run_ids.append(run.run_id)

    return live_run.run_id, run_ids


def dequeue_job(job_id):
    """Remove a job from queue if it hasn't been executed yet."""
    if job_id in default_queue.jobs:
        default_queue.remove(job_id)
    if job_id in live_queue.jobs:
        live_queue.remove(job_id)
