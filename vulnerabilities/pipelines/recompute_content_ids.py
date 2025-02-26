#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import multiprocessing
import os
import traceback
import warnings
from concurrent import futures

from aboutcode.pipeline import LoopProgress
from django.core.paginator import Paginator
from django.db import transaction

from vulnerabilities.models import Advisory
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import compute_content_id
from vulnerablecode import settings

logger = logging.getLogger("scanpipe.pipes")


def get_max_workers(keep_available=4):
    """
    Return the `VULNERABLECODE_PROCESSES` if defined in the setting,
    or returns a default value based on the number of available CPUs,
    minus the provided `keep_available` value.

    On operating system where the multiprocessing start method is not "fork",
    but for example "spawn", such as on macOS, multiprocessing and threading are
    disabled by default returning -1 `max_workers`.
    """
    processes_from_settings = settings.VULNERABLECODE_PROCESSES
    if processes_from_settings in [-1, 0, 1]:
        return processes_from_settings

    if multiprocessing.get_start_method() != "fork":
        return -1

    max_workers = os.cpu_count() - keep_available
    if max_workers < 1:
        return 1

    if processes_from_settings is not None:
        if processes_from_settings <= max_workers:
            return processes_from_settings
        else:
            msg = (
                f"The value {processes_from_settings} specified in SCANCODEIO_PROCESSES"
                f" exceeds the number of available CPUs on this machine."
                f" {max_workers} CPUs will be used instead for multiprocessing."
            )
            warnings.warn(msg, ResourceWarning)

    return max_workers


class InsufficientResourcesError(Exception):
    pass


def process_advisories(
    advisories,
    advisory_func,
    log=None,
    batch_size=1000,
):
    """
    Run the `advisory_func` on the advisories of the provided `advisories`.

    Multiprocessing is enabled by default on this pipe, the number of processes can be
    controlled through the `VULNERABLECODE_PROCESSES` setting.
    Multiprocessing can be disabled using `VULNERABLECODE_PROCESSES=0`,
    and threading can also be disabled `VULNERABLECODE_PROCESSES=-1`

    The advisories QuerySet is chunked in `batch_size` results at the time,
    this can result in a significant reduction in memory usage.
    """
    advisories_count = advisories.count()
    log(f"Process {advisories_count} advisories with {advisory_func.__name__}", level=logging.INFO)
    progress = LoopProgress(advisories_count, logger=log)
    max_workers = get_max_workers(keep_available=4)

    advisory_batches = get_advisory_batches(
        advisories=advisories,
        batch_size=batch_size,
        log=log,
    )

    log(f"Running function: {advisory_func.__name__}", level=logging.INFO)
    # if max_workers <= 0:
    if True:
        log(f"Running function in single process", level=logging.INFO)
        for advisory_ids in progress.iter(advisory_batches):
            progress.log_progress()
            advisory_func(advisory_ids=advisory_ids, logger=log)
        return

    log(
        f"Running function in multiple processes with {max_workers} max_workers", level=logging.INFO
    )

    with futures.ProcessPoolExecutor(max_workers) as executor:
        future_to_advisories = {
            executor.submit(advisory_func, advisory_ids, log): advisory_ids
            for advisory_ids in advisory_batches
        }

        future_as_completed = futures.as_completed(future_to_advisories)

        for future in progress.iter(future_as_completed):
            advisory_ids = future_to_advisories[future]
            progress.log_progress()
            try:
                future.result()
            except futures.process.BrokenProcessPool as broken_pool_error:
                message = (
                    "You may not have enough resources to complete this operation. "
                    "Please ensure that there is at least 2 GB of available memory per "
                    "CPU core for successful execution."
                )
                raise broken_pool_error from InsufficientResourcesError(message)


def get_advisory_batches(advisories, batch_size=1000, log=None):
    """
    Yield lists of advisory ids each of upto batch size length.
    """
    paginator = Paginator(advisories, per_page=batch_size)
    for page_number in paginator.page_range:
        log(f"Getting advisory batch {page_number}", level=logging.INFO)
        page = paginator.page(page_number)
        advisory_ids = None
        try:
            advisory_ids = [obj.id for obj in page.object_list]
        except Exception as e:
            if log:
                log(f"Error getting advisory batch {traceback.format_exc()}", level=logging.ERROR)
                log(f"While processing advisories {advisory_ids}", level=logging.ERROR)
            raise
        yield advisory_ids


def recompute_content_ids(advisory_ids, logger):
    """
    Recompute content IDs for all `advisory_ids`.
    """
    advisories = Advisory.objects.exclude(unique_content_id__length=64).filter(id__in=advisory_ids)
    total_count = advisories.count()

    if not total_count:
        logger("No advisories need content ID recomputation", level=logging.INFO)
        return

    logger(f"Recomputing content IDs for {total_count} advisories", level=logging.INFO)

    progress = LoopProgress(
        total_iterations=total_count,
        progress_step=total_count // 100,
        logger=logger,
    )

    with transaction.atomic():
        advisories = advisories.select_for_update(nowait=True, skip_locked=True)
        if not advisories.exists():
            return
        advisories_to_update = []
        for advisory in progress.iter(advisories):
            advisory.unique_content_id = compute_content_id(advisory.to_advisory_data())
            advisories_to_update.append(advisory)

        if advisories_to_update:
            Advisory.objects.bulk_update(
                advisories_to_update,
                ["unique_content_id"],
                batch_size=len(advisories_to_update),
            )
            if logger:
                logger(
                    f"Updated content IDs for {len(advisories_to_update)} advisories",
                    level=logging.INFO,
                )


class RecomputeContentIDPipeline(VulnerableCodePipeline):
    """Pipeline to remove duplicate advisories based on their content."""

    pipeline_id = "recompute_content_ids"
    BATCH_SIZE = 1000

    @classmethod
    def steps(cls):
        return (cls.recompute_content_ids,)

    def recompute_content_ids(self):
        """
        Recompute content IDs for all advisories.
        """
        while True:
            advisories = Advisory.objects.exclude(unique_content_id__length=64)
            print(f"advisories: {advisories.count()}")
            if not advisories.exists():
                break
            process_advisories(
                advisories=advisories,
                advisory_func=recompute_content_ids,
                log=self.log,
                batch_size=1000,
            )
