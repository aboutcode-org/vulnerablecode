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
from operator import attrgetter

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
        return (cls.remove_duplicates,)

    def remove_duplicates(self):
        """
        Find advisories with the same content and keep only the latest one.
        """
        # Get all advisories that have duplicates based on content ID
        duplicate_content_ids = (
            Advisory.objects.values("unique_content_id")
            .annotate(count=Count("id"))
            .filter(count__gt=1)
            .values_list("unique_content_id", flat=True)
        )

        self.log(
            f"Found {len(duplicate_content_ids)} content IDs with duplicates", level=logging.INFO
        )

        for content_id in duplicate_content_ids:
            # Get all advisories with this content ID
            advisories = Advisory.objects.filter(unique_content_id=content_id)

            # Find the latest advisory
            latest = advisories.latest("date_imported")

            # Delete all except the latest
            advisories.exclude(id=latest.id).delete()

            if self.log:
                self.log(
                    f"Kept advisory {latest.id} and removed "
                    f"{advisories.count() - 1} duplicates for content ID {content_id}",
                    level=logging.INFO,
                )

    def update_content_ids(self):
        """
        Update content IDs for all advisories that don't have one.
        """
        advisories = Advisory.objects.filter(
            Q(unique_content_id="") | Q(unique_content_id__isnull=True)
        )

        self.log(f"Found {advisories.count()} advisories without content ID", level=logging.INFO)

        for advisory in advisories:
            advisory.unique_content_id = compute_content_id(advisory)
            advisory.save()

            if self.log:
                self.log(f"Updated content ID for advisory {advisory.id}", level=logging.DEBUG)
