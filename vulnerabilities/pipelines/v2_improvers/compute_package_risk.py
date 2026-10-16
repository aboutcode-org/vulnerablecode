#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from urllib.parse import urlparse

from aboutcode.pipeline import LoopProgress
from django.db.models import Max
from django.db.models import Prefetch

from vulnerabilities.models import AdvisoryExploit
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.risk_score import bulk_update
from vulnerabilities.severity_systems import EPSS
from vulnerabilities.weight_config import WEIGHT_CONFIG

DEFAULT_WEIGHT = 5


class ComputePackageRiskPipeline(VulnerableCodePipeline):
    """
    Compute risk score for packages.

    See https://github.com/aboutcode-org/vulnerablecode/issues/1543
    """

    pipeline_id = "compute_package_risk_v2"
    license_expression = None

    # Run pipeline every 30 minutes.
    run_interval = 30
    run_priority = PipelineSchedule.ExecutionPriority.HIGH

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

        latest_advisories = AdvisoryV2.objects.latest_completely_imported_advisories_per_avid()

        qs = (
            PackageV2.objects.filter(
                affected_in_impacts__advisory__risk_score__isnull=False,
                affected_in_impacts__advisory__in=latest_advisories,
            )
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


def compute_vulnerability_risk_factors(references, severities, exploits):
    """
    Risk may be expressed as a number ranging from 0 to 10.
    Risk is calculated from weighted severity and exploitability values.
    It is the maximum value of (the weighted severity multiplied by its exploitability) or 10

    Risk = min(weighted severity * exploitability, 10)
    """
    weighted_severity = get_weighted_severity(severities)
    exploitability = get_exploitability_level(exploits, references, severities)
    return weighted_severity, exploitability


def get_weighted_severity(severities):
    """
    Weighted Severity is the maximum value obtained when each Severity is multiplied
    by its associated Weight/10.
    Example of Weighted Severity: max(7*(10/10), 8*(3/10), 6*(8/10)) = 7
    """
    if not severities:
        return 0

    score_map = {
        "low": 3,
        "moderate": 6.9,
        "medium": 6.9,
        "high": 8.9,
        "important": 8.9,
        "critical": 10.0,
        "urgent": 10.0,
    }

    score_list = []
    for severity in severities:
        if not severity.url:
            continue
        parsed_url = urlparse(severity.url)
        severity_source = parsed_url.netloc.replace("www.", "", 1)
        weight = WEIGHT_CONFIG.get(severity_source, DEFAULT_WEIGHT)
        max_weight = float(weight) / 10
        vul_score = severity.value
        if not vul_score:
            continue
        try:
            vul_score = float(vul_score)
            vul_score_value = vul_score * max_weight
        except ValueError:
            vul_score = vul_score.lower()
            vul_score_value = score_map.get(vul_score, 0) * max_weight

        score_list.append(vul_score_value)

    max_score = max(score_list) if score_list else 0
    return round(max_score, 1)


def get_exploitability_level(exploits, references, severities):
    """
    Exploitability refers to the potential or
    probability of a software package vulnerability being exploited by
    malicious actors to compromise systems, applications, or networks.
    It is determined automatically by discovery of exploits.
    """
    # no exploit known ( default .5)
    exploit_level = 0.5

    if exploits:
        # Automatable Exploit with PoC script published OR known exploits (KEV) in the wild OR known ransomware
        exploit_level = 2

    elif severities:
        # high EPSS.
        for severity in severities:
            if severity.scoring_system == EPSS.identifier and float(severity.value) > 0.8:
                exploit_level = 2
                break

    elif references:
        # PoC/Exploit script published
        for reference in references:
            if reference.reference_type == AdvisoryReference.EXPLOIT:
                exploit_level = 1
                break

    return exploit_level
