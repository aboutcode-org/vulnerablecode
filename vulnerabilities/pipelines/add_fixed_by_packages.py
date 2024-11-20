#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from aboutcode.pipeline import LoopProgress
from django.db import transaction

from vulnerabilities.models import AffectedByPackageRelatedVulnerability, FixingPackageRelatedVulnerability, Package
from vulnerabilities.pipelines import VulnerableCodePipeline


class ComputeFixedByPackagesPipeline(VulnerableCodePipeline):
    """
    Compute and populate the `fixed_by_packages` field in AffectedByPackageRelatedVulnerability.

    See https://github.com/aboutcode-org/vulnerablecode/issues/1543
    """

    pipeline_id = "compute_fixed_by_packages"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.compute_and_store_fixed_by_packages,)

    def compute_and_store_fixed_by_packages(self):
        affected_relationships = AffectedByPackageRelatedVulnerability.objects.all()

        self.log(f"Calculating `fixed_by_packages` for {affected_relationships.count():,d} records")

        progress = LoopProgress(
            total_iterations=affected_relationships.count(),
            logger=self.log,
            progress_step=5,
        )

        updated_relationship_count = 0

        for relationship in progress.iter(affected_relationships):
            # Get fixing packages for this relationship
            fixing_package_ids = FixingPackageRelatedVulnerability.objects.filter(
                package__name=relationship.package.name,
                package__type=relationship.package.type,
                package__namespace=relationship.package.namespace,
                vulnerability=relationship.vulnerability,
            ).values_list("package__id", flat=True)

            # Update the ManyToMany field using the provided method
            self.update_fixed_by_packages(relationship, fixing_package_ids)
            updated_relationship_count += 1

        self.log(
            f"Successfully populated `fixed_by_packages` for {updated_relationship_count:,d} records"
        )

    @transaction.atomic
    def update_fixed_by_packages(self, relationship, fixing_package_ids):
        """
        Update the fixed_by_packages field for a given relationship.
        """
        # Clear existing relations and add new ones
        relationship.fixed_by_packages.clear()
        packages = Package.objects.filter(id__in=fixing_package_ids)
        relationship.fixed_by_packages.add(*packages)
