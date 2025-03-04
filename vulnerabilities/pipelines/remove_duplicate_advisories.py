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
    """Pipeline to remove duplicate advisories based on their content."""

    pipeline_id = "remove_duplicate_advisories"

    @classmethod
    def steps(cls):
        return (cls.remove_duplicates,)

    def remove_duplicates(self):
        """
        Recompute content id and remove advisories with the same content and keep only the latest one.
        """

        advisories_count = Advisory.objects.all().count()
        self.log(f"Computing new content id for {advisories_count} and removing duplicates.")

        update_batch_size = 500
        delete_batch_size = 1000
        chunk_size = 50000
        deleted_advisory_count = 0
        updated_advisory_count = 0
        duplicate_advisory_id = []
        updated_advisory = []
        content_ids = set()

        advisories = Advisory.objects.all().order_by("-id").paginated(per_page=chunk_size)
        progress = LoopProgress(
            total_iterations=advisories_count,
            logger=self.log,
            progress_step=1,
        )

        for advisory in progress.iter(advisories):
            content_id = compute_content_id(advisory.to_advisory_data())
            if content_id in content_ids:
                duplicate_advisory_id.append(advisory.id)
            else:
                if advisory.unique_content_id != content_id:
                    advisory.unique_content_id = content_id
                    updated_advisory.append(advisory)
                    content_ids.add(content_id)
            if len(duplicate_advisory_id) > delete_batch_size:
                deleted_advisory_count += delete_advisories(
                    advisory_ids=duplicate_advisory_id,
                    logger=self.log,
                )
            if len(updated_advisory) > update_batch_size:
                updated_advisory_count += bulk_update_advisory(
                    items=updated_advisory,
                    fields=["unique_content_id"],
                    logger=self.log,
                )

        deleted_advisory_count += delete_advisories(
            advisory_ids=duplicate_advisory_id,
            logger=self.log,
        )
        updated_advisory_count += bulk_update_advisory(
            items=updated_advisory,
            fields=["unique_content_id"],
            logger=self.log,
        )

        self.log(f"Removed {deleted_advisory_count} duplicates advisories.")
        self.log(f"Updated content id for {deleted_advisory_count} advisories.")


def bulk_update_advisory(items, fields, logger):
    item_count = 0
    if items:
        try:
            Advisory.objects.bulk_update(objs=items, fields=fields)
            item_count += len(items)
        except Exception as e:
            logger(f"Error updating Advisory: {e}")
        items.clear()
    return item_count


def delete_advisories(advisory_ids, logger):
    item_count = 0
    if advisory_ids:
        try:
            Advisory.objects.filter(id__in=advisory_ids).delete()
            item_count += len(advisory_ids)
        except Exception as e:
            logger(f"Error deleting Advisory: {e}")
        advisory_ids.clear()
    return item_count
