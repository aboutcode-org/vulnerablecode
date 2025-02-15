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
from django.db.models import Count
from django.db.models import Q

from vulnerabilities.models import Advisory
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import compute_content_id


class RemoveDuplicateAdvisoriesPipeline(VulnerableCodePipeline):
    """Pipeline to remove duplicate advisories based on their content."""

    pipeline_id = "remove_duplicate_advisories"

    @classmethod
    def steps(cls):
        return (
            cls.recompute_content_ids,
            cls.remove_duplicates,
        )

    def remove_duplicates(self):
        """
        Find advisories with the same content and keep only the latest one.
        """

        duplicated_advisories = groupby(
            Advisory.objects.order_by("unique_content_id").all().paginated(),
            key=lambda x: x.unique_content_id,
        )
        progress = LoopProgress(total_iterations=Advisory.objects.count(), logger=self.log)
        for _content_id, advisories in progress.iter(duplicated_advisories):
            advisories = list(advisories)
            self.log(
                f"Removing duplicates for content ID {_content_id} {len(advisories)}",
                level=logging.INFO,
            )
            oldest = min(advisories, key=lambda x: x.date_imported)
            try:
                advisory_ids = []
                for adv in advisories:
                    if adv.id != oldest.id:
                        advisory_ids.append(adv.id)
                Advisory.objects.filter(id__in=advisory_ids).delete()
            except Exception as e:
                self.log(f"Error deleting advisories: {e}", level=logging.ERROR)

            self.log(
                f"Kept advisory {oldest.id} and removed "
                f"{len(list(advisories)) - 1} duplicates for content ID {_content_id}",
                level=logging.INFO,
            )

    def recompute_content_ids(self):
        """
        Recompute content IDs for all advisories.
        """

        advisories = []

        advisories = Advisory.objects.exclude(unique_content_id__length=64)

        progress = LoopProgress(
            total_iterations=advisories.count(),
            progress_step=1000,
            logger=self.log,
        )

        batch_size = 50000

        for advisory in progress.iter(advisories.paginated(per_page=batch_size)):
            advisory.unique_content_id = compute_content_id(advisory.to_advisory_data())
            advisories.append(advisory)
            if len(advisories) % batch_size == 0:
                Advisory.objects.bulk_update(
                    advisories, ["unique_content_id"], batch_size=batch_size
                )
                advisories = []

        if advisories:
            Advisory.objects.bulk_update(advisories, ["unique_content_id"], batch_size=batch_size)
