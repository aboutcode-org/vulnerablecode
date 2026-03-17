#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from aboutcode.pipeline import LoopProgress
from django.db.models import Max
from django.db.models import Prefetch

from vulnerabilities.models import AdvisoryExploit
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
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
            AdvisoryV2.objects.latest_per_avid()
            .filter(impacted_packages__affecting_packages__isnull=False)
            .only("id")
            .prefetch_related(
                Prefetch(
                    "references", queryset=AdvisoryReference.objects.only("id", "reference_type")
                ),
                Prefetch(
                    "severities",
                    queryset=AdvisorySeverity.objects.only("id", "value", "url", "scoring_system"),
                ),
                Prefetch("exploits", queryset=AdvisoryExploit.objects.only("id")),
                Prefetch(
                    "related_advisory_severities",
                    queryset=AdvisoryV2.objects.only("id").prefetch_related(
                        Prefetch(
                            "severities",
                            queryset=AdvisorySeverity.objects.only(
                                "id", "value", "url", "scoring_system"
                            ),
                        )
                    ),
                ),
            )
            .distinct()
        )

        estimated_vulnerability_count = affected_advisories.count()

        self.log(
            f"Calculating risk for {estimated_vulnerability_count:,d} advisory with a affected packages records"
        )

        progress = LoopProgress(
            logger=self.log, total_iterations=estimated_vulnerability_count, progress_step=5
        )

        updatables = []
        updated_vulnerability_count = 0
        batch_size = 5000

        for advisory in progress.iter(affected_advisories.iterator(chunk_size=batch_size)):

            references = advisory.references.all()
            exploits = advisory.exploits.all()

            severities = list(advisory.severities.all())

            for rel in advisory.related_advisory_severities.all():
                severities.extend(rel.severities.all())

            try:
                weighted_severity, exploitability = compute_vulnerability_risk_factors(
                    references=references,
                    severities=severities,
                    exploits=exploits,
                )

                advisory.weighted_severity = weighted_severity
                advisory.exploitability = exploitability
                if advisory.exploitability and advisory.weighted_severity:
                    risk_score = min(
                        float(advisory.exploitability * advisory.weighted_severity), 10.0
                    )
                    advisory.risk_score = round(risk_score, 1)
                updatables.append(advisory)
            except Exception as e:
                self.log(f"Error computing risk score for advisory {advisory.advisory_id}: {e}")

            if len(updatables) >= batch_size:
                updated_vulnerability_count += bulk_update(
                    model=AdvisoryV2,
                    items=updatables,
                    fields=["weighted_severity", "exploitability", "risk_score"],
                    logger=self.log,
                )
                updatables.clear()

        if updatables:
            updated_vulnerability_count += bulk_update(
                model=AdvisoryV2,
                items=updatables,
                fields=["weighted_severity", "exploitability", "risk_score"],
                logger=self.log,
            )

        self.log(
            f"Successfully added risk score for {updated_vulnerability_count:,d} vulnerability"
        )

    def compute_and_store_package_risk_score(self):
        qs = (
            PackageV2.objects.filter(affected_in_impacts__advisory__risk_score__isnull=False)
            .annotate(computed_risk=Max("affected_in_impacts__advisory__risk_score"))
            .only("id")
        )

        estimated = qs.count()

        progress = LoopProgress(
            total_iterations=estimated,
            logger=self.log,
            progress_step=5,
        )

        self.log(f"Computing risk for {estimated:,d} packages")

        batch = []
        batch_size = 5000
        updated = 0

        for pkg in progress.iter(qs.iterator(chunk_size=batch_size)):

            pkg.risk_score = round(float(pkg.computed_risk), 1)
            batch.append(pkg)

            if len(batch) >= batch_size:
                updated += bulk_update(
                    model=PackageV2,
                    items=batch,
                    fields=["risk_score"],
                    logger=self.log,
                )
                batch.clear()

        updated += bulk_update(
            model=PackageV2,
            items=batch,
            fields=["risk_score"],
            logger=self.log,
        )
        self.log(f"Successfully added risk score for {updated:,d} package")


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
