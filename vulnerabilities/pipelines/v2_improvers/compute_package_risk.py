#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from aboutcode.pipeline import LoopProgress
from django.db.models import Prefetch
from django.db.models import Q

from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.risk import compute_package_risk_v2
from vulnerabilities.risk import compute_vulnerability_risk_factors


class ComputePackageRiskPipeline(VulnerableCodePipeline):
    """
    Compute risk score for packages.

    See https://github.com/aboutcode-org/vulnerablecode/issues/1543
    """

    pipeline_id = "compute_package_risk_v2"
    license_expression = None

    @classmethod
    def steps(cls):
        return (
            cls.compute_and_store_vulnerability_risk_score,
            cls.compute_and_store_package_risk_score,
        )

    def compute_and_store_vulnerability_risk_score(self):
        affected_advisories = (
            AdvisoryV2.objects.filter(impacted_packages__affecting_packages__isnull=False)
            .prefetch_related(
                "references",
                "severities",
                "exploits",
                Prefetch(
                    "related_advisory_severities",
                    queryset=AdvisoryV2.objects.prefetch_related("severities"),
                ),
            )
            .distinct()
        )

        self.log(
            f"Calculating risk for {affected_advisories.count():,d} advisory with a affected packages records"
        )

        progress = LoopProgress(total_iterations=affected_advisories.count(), logger=self.log)

        updatables = []
        updated_vulnerability_count = 0
        batch_size = 5000

        for advisory in progress.iter(affected_advisories.iterator(chunk_size=batch_size)):
            references = advisory.references.all()
            exploits = advisory.exploits.all()

            severities = AdvisorySeverity.objects.filter(
                Q(advisories=advisory) | Q(advisories__related_to_advisory_severities=advisory)
            ).distinct()

            weighted_severity, exploitability = compute_vulnerability_risk_factors(
                references=references,
                severities=severities,
                exploits=exploits,
            )
            advisory.weighted_severity = weighted_severity
            advisory.exploitability = exploitability
            updatables.append(advisory)

            if len(updatables) >= batch_size:
                updated_vulnerability_count += bulk_update(
                    model=AdvisoryV2,
                    items=updatables,
                    fields=["weighted_severity", "exploitability"],
                    logger=self.log,
                )

        updated_vulnerability_count += bulk_update(
            model=AdvisoryV2,
            items=updatables,
            fields=["weighted_severity", "exploitability"],
            logger=self.log,
        )

        self.log(
            f"Successfully added risk score for {updated_vulnerability_count:,d} vulnerability"
        )

    def compute_and_store_package_risk_score(self):
        affected_packages = (PackageV2.objects.filter(affected_in_impacts__isnull=False)).distinct()

        self.log(f"Calculating risk for {affected_packages.count():,d} affected package records")

        progress = LoopProgress(
            total_iterations=affected_packages.count(),
            logger=self.log,
            progress_step=5,
        )

        updatables = []
        updated_package_count = 0
        batch_size = 10000

        for package in progress.iter(affected_packages.iterator(chunk_size=batch_size)):
            risk_score = compute_package_risk_v2(package)

            if not risk_score:
                continue

            package.risk_score = risk_score
            updatables.append(package)

            if len(updatables) >= batch_size:
                updated_package_count += bulk_update(
                    model=PackageV2,
                    items=updatables,
                    fields=["risk_score"],
                    logger=self.log,
                )
        updated_package_count += bulk_update(
            model=PackageV2,
            items=updatables,
            fields=["risk_score"],
            logger=self.log,
        )
        self.log(f"Successfully added risk score for {updated_package_count:,d} package")


def bulk_update(model, items, fields, logger):
    item_count = 0
    if items:
        try:
            model.objects.bulk_update(objs=items, fields=fields)
            item_count += len(items)
        except Exception as e:
            logger(f"Error updating {model.__name__}: {e}")
        items.clear()
    return item_count
