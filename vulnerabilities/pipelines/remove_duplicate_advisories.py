#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress

from vulnerabilities.models import Advisory
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import compute_content_id


class RemoveDuplicateAdvisoriesPipeline(VulnerableCodePipeline):
    """Pipeline to compute new advisory content id and remove duplicate advisories based on their content."""

    pipeline_id = "remove_duplicate_advisories"

    @classmethod
    def steps(cls):
        return (cls.remove_duplicates,)

    def remove_duplicates(self):
        """
        Recompute the content ID and remove duplicate advisories, keeping the oldest one.
        """

        advisories_count = Advisory.objects.all().count()
        self.log(f"Computing new content id for {advisories_count} and removing duplicates.")

        update_batch_size = 500
        delete_batch_size = 5000
        chunk_size = 5000
        deleted_advisories_count = 0
        updated_advisories_count = 0
        duplicate_advisory_ids = []
        advisories_to_update = []
        content_ids = set()

        advisories = Advisory.objects.all().order_by("id").iterator(chunk_size=chunk_size)

        progress = LoopProgress(
            total_iterations=advisories_count,
            logger=self.log,
            progress_step=1,
        )

        for advisory in progress.iter(advisories):
            content_id = compute_content_id(advisory.to_advisory_data())

            if content_id in content_ids:
                duplicate_advisory_ids.append(advisory.id)
            else:
                content_ids.add(content_id)
                if advisory.unique_content_id != content_id:
                    advisory.unique_content_id = content_id
                    advisories_to_update.append(advisory)

            if len(duplicate_advisory_ids) > delete_batch_size:
                deleted_advisories_count += delete_advisories(
                    advisory_ids=duplicate_advisory_ids,
                    logger=self.log,
                )
                duplicate_advisory_ids.clear()

            if len(advisories_to_update) > update_batch_size:
                updated_advisories_count += bulk_update_advisories(
                    advisories=advisories_to_update,
                    fields=["unique_content_id"],
                    logger=self.log,
                )
                advisories_to_update.clear()

        deleted_advisories_count += delete_advisories(
            advisory_ids=duplicate_advisory_ids,
            logger=self.log,
        )
        updated_advisories_count += bulk_update_advisories(
            advisories=advisories_to_update,
            fields=["unique_content_id"],
            logger=self.log,
        )

        self.log(f"Removed {deleted_advisories_count} duplicates advisories.")
        self.log(f"Updated content id for {deleted_advisories_count} advisories.")


def bulk_update_advisories(advisories, fields, logger):
    item_count = 0
    if advisories:
        try:
            Advisory.objects.bulk_update(objs=advisories, fields=fields)
            item_count += len(advisories)
        except Exception as e:
            logger(f"Error updating Advisory: {e}")
    return item_count


def delete_advisories(advisory_ids, logger):
    item_count = 0
    if advisory_ids:
        try:
            Advisory.objects.filter(id__in=advisory_ids).delete()
            item_count += len(advisory_ids)
        except Exception as e:
            logger(f"Error deleting Advisory: {e}")
    return item_count
