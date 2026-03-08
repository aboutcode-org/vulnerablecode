#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from typing import Iterable
from typing import Mapping

from packageurl import PackageURL
from univers.version_range import ArchLinuxVersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import fetch_response


class ArchLinuxImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """ArchLinux Importer Pipeline"""

    pipeline_id = "archlinux_importer_v2"
    spdx_license_expression = "MIT"
    license_url = "https://github.com/archlinux/arch-security-tracker/blob/master/LICENSE"

    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self) -> Iterable[Mapping]:
        url = "https://security.archlinux.org/json"
        self.log(f"Fetching `{url}`")
        response = fetch_response(url)
        self.response = response.json()

    def advisories_count(self) -> int:
        return len(self.response)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for record in self.response:
            yield self.parse_advisory(record)

    def parse_advisory(self, record) -> AdvisoryDataV2:
        affected_packages = []
        references = []
        severities = []
        avg_name = record.get("name")
        severity = record.get("severity")
        aliases = record.get("issues", [])
        aliases.extend(record.get("advisories", []))
        summary = record.get("type", "")
        summary = "" if summary == "unknown" else summary

        for name in record["packages"]:
            affected = record.get("affected")
            fixed = record.get("fixed")

            affected_version_range = (
                ArchLinuxVersionRange.from_versions([affected]) if affected else None
            )
            fixed_version_range = ArchLinuxVersionRange.from_versions([fixed]) if fixed else None
            affected_package = AffectedPackageV2(
                package=PackageURL(
                    name=name,
                    type="alpm",
                    namespace="archlinux",
                ),
                affected_version_range=affected_version_range,
                fixed_version_range=fixed_version_range,
            )
            affected_packages.append(affected_package)

        references.append(
            ReferenceV2(
                reference_id=avg_name,
                url="https://security.archlinux.org/{}".format(avg_name),
            )
        )
        for ref in record["advisories"]:
            references.append(
                ReferenceV2(
                    reference_id=ref,
                    url="https://security.archlinux.org/{}".format(ref),
                )
            )

        if severity not in severity_systems.ARCHLINUX.choices:
            self.log(f"Unknown severity {severity} for {avg_name}")
            severity = None
        if severity:
            severities = [
                VulnerabilitySeverity(
                    system=severity_systems.ARCHLINUX,
                    value=severity,
                    url="https://security.archlinux.org/{avg_name}.json",
                )
            ]

        return AdvisoryDataV2(
            advisory_id=avg_name,
            aliases=aliases,
            summary=summary,
            references=references,
            affected_packages=affected_packages,
            severities=severities,
            weaknesses=[],
            url=f"https://security.archlinux.org/{avg_name}.json",
            original_advisory_text=json.dumps(record, indent=2, ensure_ascii=False),
        )
