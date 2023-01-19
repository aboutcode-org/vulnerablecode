#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from typing import Iterable

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.utils import fetch_yaml
from vulnerabilities.utils import is_cve

URL = "https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml"


class SUSESeverityScoreImporter(Importer):

    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://ftp.suse.com/pub/projects/security/yaml/LICENSE"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        score_data = fetch_yaml(URL)
        yield from self.to_advisory(score_data)

    def to_advisory(self, score_data):
        systems_by_version = {
            "2.0": severity_systems.CVSSV2,
            "3": severity_systems.CVSSV3,
            "3.1": severity_systems.CVSSV31,
        }

        for cve_id in score_data or []:
            severities = []
            for cvss_score in score_data[cve_id].get("cvss") or []:
                cvss_version = cvss_score.get("version") or ""
                scoring_system = systems_by_version.get(cvss_version)
                if not scoring_system:
                    continue
                base_score = str(cvss_score.get("score") or "")
                vector = str(cvss_score.get("vector") or "")
                score = VulnerabilitySeverity(
                    system=scoring_system,
                    value=base_score,
                    scoring_elements=vector,
                )
                severities.append(score)

            if not is_cve(cve_id):
                continue

            yield AdvisoryData(
                aliases=[cve_id],
                summary="",
                references=[Reference(url=URL, severities=severities)],
            )
