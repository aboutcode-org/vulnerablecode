#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from itertools import groupby

from aboutcode.pipeline import LoopProgress
from django.db import transaction
from django.db.models import Count

from vulnerabilities.models import Advisory
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipelines.recompute_content_ids import process_advisories


def remove_duplicates_batch(advisory_ids, logger=None):
    """
    Process a batch of advisories to remove duplicates.
    Keep only the oldest advisory for each content ID.
    """
    try:
        with transaction.atomic():
            advisories = Advisory.objects.filter(id__in=advisory_ids).select_for_update(
                skip_locked=True
            )
            if not advisories.exists():
                return

            advisories_by_content_id = groupby(
                advisories.order_by("unique_content_id").paginated(),
                key=lambda x: x.unique_content_id,
            )

            progress = LoopProgress(total_iterations=advisories.count(), logger=logger)

            for content_id, group_advisories in progress.iter(advisories_by_content_id):
                group_advisories = list(group_advisories)

                if len(group_advisories) <= 1:
                    continue

                logger(
                    f"Found {len(group_advisories)} duplicates for content ID {content_id}",
                )

                oldest = min(group_advisories, key=lambda x: x.date_imported)

                advisory_ids_to_delete = [adv.id for adv in group_advisories if adv.id != oldest.id]
                if advisory_ids_to_delete:
                    Advisory.objects.filter(id__in=advisory_ids_to_delete).delete()
                    logger(
                        f"Kept advisory {oldest.id} and removed "
                        f"{len(advisory_ids_to_delete)} duplicates for content ID {content_id}",
                    )

    except Exception as e:
        logger(
            f"Error processing batch of advisories: {e}",
            level=logging.ERROR,
        )


class RemoveDuplicateAdvisoriesPipeline(VulnerableCodePipeline):
    """Pipeline to remove duplicate advisories based on their content."""

    pipeline_id = "remove_duplicate_advisories"
    BATCH_SIZE = 1000

    @classmethod
    def steps(cls):
        return (cls.remove_duplicates,)

    def remove_duplicates(self):
        """
        Find advisories with the same content and keep only the oldest one.
        Process in parallel batches with proper transaction management.
        """
        while True:
            duplicate_content_ids = (
                Advisory.objects.values("unique_content_id")
                .annotate(count=Count("id"))
                .filter(count__gt=1)
                .values_list("unique_content_id", flat=True)
            )
            advisories = Advisory.objects.filter(unique_content_id__in=duplicate_content_ids)
            if not advisories.exists():
                break

            self.log(
                f"Processing {advisories.count()} content IDs with duplicates",
                level=logging.INFO,
            )
            process_advisories(
                advisories=advisories,
                advisory_func=remove_duplicates_batch,
                progress_logger=self.log,
                batch_size=self.BATCH_SIZE,
            )

            self.log("Completed duplicate removal batch", level=logging.INFO)
