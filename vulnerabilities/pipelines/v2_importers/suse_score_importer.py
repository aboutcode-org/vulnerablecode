#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from typing import Iterable

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.management.commands.commit_export import logger
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import fetch_yaml


class SUSESeverityScoreImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://ftp.suse.com/pub/projects/security/yaml/LICENSE"
    pipeline_id = "suse_importer_v2"
    url = "https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml"

    @classmethod
    def steps(cls):
        return (
            cls.fetch_advisories,
            cls.collect_and_store_advisories,
        )

    def fetch_advisories(self):
        self.score_data = fetch_yaml(self.url)

    def advisories_count(self):
        return sum(1 for _ in self.score_data)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        systems_by_version = {
            "2.0": severity_systems.CVSSV2,
            "3": severity_systems.CVSSV3,
            "3.1": severity_systems.CVSSV31,
            "4": severity_systems.CVSSV4,
        }

        for cve_id in self.score_data or []:
            severities = []
            for cvss_score in self.score_data[cve_id].get("cvss") or []:
                cvss_version = cvss_score.get("version") or ""
                scoring_system = systems_by_version.get(cvss_version)
                if not scoring_system:
                    logger.error(f"Unsupported CVSS version: {cvss_version}")
                    continue
                base_score = str(cvss_score.get("score") or "")
                vector = str(cvss_score.get("vector") or "")
                score = VulnerabilitySeverity(
                    system=scoring_system,
                    value=base_score,
                    scoring_elements=vector,
                )
                severities.append(score)

            yield AdvisoryData(
                advisory_id=cve_id,
                aliases=[],
                summary="",
                severities=severities,
                references_v2=[ReferenceV2(reference_id=cve_id, url=self.url)],
                url=self.url,
            )
