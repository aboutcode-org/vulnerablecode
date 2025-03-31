# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import re

from aboutcode.pipeline import LoopProgress
from django.db import transaction

from vulnerabilities import severity_systems
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodePipeline


class CVEAdvisoryMappingPipeline(VulnerableCodePipeline):
    """
    Pipeline to map CVEs from VulnerabilitySeverity to corresponding Advisories with CVSS3.1 scores.
    """

    pipeline_id = "add_cvssv3.1_to_CVEs"

    @classmethod
    def steps(cls):
        return (cls.process_cve_advisory_mapping,)

    def process_cve_advisory_mapping(self):
        nvd_severities = (
            VulnerabilitySeverity.objects.filter(
                url__startswith="https://nvd.nist.gov/vuln/detail/CVE-", scoring_system="cvssv3"
            )
            .prefetch_related("vulnerabilities")
            .distinct()
        )

        self.log(f"Processing {nvd_severities.count():,d} CVE severity records")

        progress = LoopProgress(
            total_iterations=nvd_severities.count(),
            logger=self.log,
            progress_step=5,
        )

        batch_size = 1000
        results = []

        for severity in progress.iter(nvd_severities.paginated(per_page=batch_size)):
            cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,7})").search
            cve_match = cve_pattern(severity.url)
            if cve_match:
                cve_id = cve_match.group()
            else:
                self.log(f"Could not find CVE ID in URL: {severity.url}")
                continue

            if matching_alias := Alias.objects.get(alias=cve_id):
                matching_advisories = matching_alias.advisories.filter(created_by="nvd_importer")

            for advisory in matching_advisories or []:
                for reference in advisory.references:
                    for sev in reference.get("severities", []):
                        if sev.get("system") == "cvssv3.1":
                            results.append(
                                {
                                    "cve_id": cve_id,
                                    "cvss31_score": sev.get("value"),
                                    "cvss31_vector": sev.get("scoring_elements"),
                                    "vulnerabilities": severity.vulnerabilities.all(),
                                }
                            )

        if results:
            self._process_batch(results)

        self.log(f"Completed processing CVE to Advisory mappings")

    def _process_batch(self, results):
        """
        Process a batch of results. Transactions are used to ensure data consistency.
        """
        self.log(f"Processing batch of {len(results)} mappings")

        with transaction.atomic():
            for result in results:
                self.log(
                    f"CVE: {result['cve_id']}, "
                    f"CVSS3.1: {result['cvss31_score']}, "
                    f"Vector: {result['cvss31_vector']}"
                )

                for vulnerability in result["vulnerabilities"]:
                    vuln_severity, _ = VulnerabilitySeverity.objects.update_or_create(
                        scoring_system=severity_systems.CVSSV31.identifier,
                        url=f"https://nvd.nist.gov/vuln/detail/{result['cve_id']}",
                        value=result["cvss31_score"],
                        scoring_elements=result["cvss31_vector"],
                    )
                    vulnerability.severities.add(vuln_severity)
