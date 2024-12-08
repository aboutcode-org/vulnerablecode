#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from itertools import groupby

from aboutcode.pipeline import LoopProgress
from django.db import transaction
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.versions import Version

from vulnerabilities.models import Package
from vulnerabilities.pipelines import VulnerableCodePipeline


class ComputeVersionRankPipeline(VulnerableCodePipeline):
    """
    A pipeline to compute and assign version ranks for all packages.
    """

    pipeline_id = "compute_version_rank"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.compute_and_store_version_rank,)

    def compute_and_store_version_rank(self):
        """
        Compute and assign version ranks to all packages.
        """
        groups = Package.objects.only("type", "namespace", "name").order_by(
            "type", "namespace", "name"
        )

        def key(package):
            return package.type, package.namespace, package.name

        groups = groupby(groups, key=key)

        groups = [(list(x), list(y)) for x, y in groups]

        total_groups = len(groups)
        self.log(f"Calculating `version_rank` for {total_groups:,d} groups of packages.")

        progress = LoopProgress(
            total_iterations=total_groups,
            logger=self.log,
            progress_step=5,
        )

        for group, packages in progress.iter(groups):
            type, namespace, name = group
            if type not in RANGE_CLASS_BY_SCHEMES:
                continue
            self.update_version_rank_for_group(packages)

        self.log("Successfully populated `version_rank` for all packages.")

    @transaction.atomic
    def update_version_rank_for_group(self, packages):
        """
        Update the `version_rank` for all packages in a specific group.
        """

        # Sort the packages by version
        sorted_packages = self.sort_packages_by_version(packages)

        # Assign version ranks
        updates = []
        for rank, package in enumerate(sorted_packages, start=1):
            package.version_rank = rank
            updates.append(package)

        # Bulk update to save the ranks
        Package.objects.bulk_update(updates, fields=["version_rank"])

    def sort_packages_by_version(self, packages):
        """
        Sort packages by version using `version_class`.
        """

        if not packages:
            return []
        version_class = RANGE_CLASS_BY_SCHEMES.get(packages[0].type).version_class
        if not version_class:
            version_class = Version
        return sorted(packages, key=lambda p: version_class(p.version))
