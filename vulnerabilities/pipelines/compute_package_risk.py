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

from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.risk import compute_package_risk
from vulnerabilities.risk import compute_vulnerability_risk_factors


class ComputePackageRiskPipeline(VulnerableCodePipeline):
    """
    Compute risk score for packages.

    See https://github.com/aboutcode-org/vulnerablecode/issues/1543
    """

    pipeline_id = "compute_package_risk"
    license_expression = None

    @classmethod
    def steps(cls):
        return (
            cls.compute_and_store_vulnerability_risk_score,
            cls.compute_and_store_package_risk_score,
        )

    def compute_and_store_vulnerability_risk_score(self):
        affected_vulnerabilities = (
            Vulnerability.objects.filter(affecting_packages__isnull=False)
            .prefetch_related(
                "references",
                "severities",
                "exploits",
            )
            .distinct()
        )

        self.log(
            f"Calculating risk for {affected_vulnerabilities.count():,d} vulnerability with a affected packages records"
        )

        progress = LoopProgress(total_iterations=affected_vulnerabilities.count(), logger=self.log)

        updatables = []
        updated_vulnerability_count = 0
        batch_size = 5000

        for vulnerability in progress.iter(affected_vulnerabilities.paginated(per_page=batch_size)):
            severities = vulnerability.severities.all()
            references = vulnerability.references.all()
            exploits = vulnerability.exploits.all()

            weighted_severity, exploitability = compute_vulnerability_risk_factors(
                references=references,
                severities=severities,
                exploits=exploits,
            )
            vulnerability.weighted_severity = weighted_severity
            vulnerability.exploitability = exploitability

            updatables.append(vulnerability)

            if len(updatables) >= batch_size:
                updated_vulnerability_count += bulk_update(
                    model=Vulnerability,
                    items=updatables,
                    fields=["weighted_severity", "exploitability"],
                    logger=self.log,
                )

        updated_vulnerability_count += bulk_update(
            model=Vulnerability,
            items=updatables,
            fields=["weighted_severity", "exploitability"],
            logger=self.log,
        )

        self.log(
            f"Successfully added risk score for {updated_vulnerability_count:,d} vulnerability"
        )

    def compute_and_store_package_risk_score(self):
        affected_packages = (
            Package.objects.filter(affected_by_vulnerabilities__isnull=False).prefetch_related(
                Prefetch(
                    "affectedbypackagerelatedvulnerability_set__vulnerability",
                    queryset=Vulnerability.objects.only("weighted_severity", "exploitability"),
                ),
            )
        ).distinct()

        self.log(f"Calculating risk for {affected_packages.count():,d} affected package records")

        progress = LoopProgress(
            total_iterations=affected_packages.count(),
            logger=self.log,
            progress_step=5,
        )

        updatables = []
        updated_package_count = 0
        batch_size = 10000

        for package in progress.iter(affected_packages.paginated(per_page=batch_size)):
            risk_score = compute_package_risk(package)

            if not risk_score:
                continue

            package.risk_score = risk_score
            updatables.append(package)

            if len(updatables) >= batch_size:
                updated_package_count += bulk_update(
                    model=Package,
                    items=updatables,
                    fields=["risk_score"],
                    logger=self.log,
                )
        updated_package_count += bulk_update(
            model=Package,
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
