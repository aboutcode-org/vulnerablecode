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

from packageurl import PackageURL
from univers.version_range import GitHubVersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import is_cve

MM_REPO = {
    "Mattermost Mobile Apps": "mattermost-mobile",
    "Mattermost Server": "mattermost-server",
    "Mattermost Desktop App": "desktop",
    "Mattermost Boards": "mattermost-plugin-boards",
    "Mattermost Plugins": "mattermost-plugin-github",
}


class MattermostImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Importer for Xen Security Advisories from xsa.json.
    """

    pipeline_id = "mattermost_importer_v2"
    url = "https://securityupdates.mattermost.com/security_updates.json"
    spdx_license_expression = "LicenseRef-scancode-other-permissive"

    _cached_data = None  # Class-level cache

    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def get_mattermost_data(self):
        if self._cached_data is None:
            self._cached_data = fetch_response(self.url).json()
        return self._cached_data

    def advisories_count(self) -> int:
        data = self.get_mattermost_data()
        return len(data) if data else 0

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        data = self.get_mattermost_data()
        if not data:
            return

        for advisory in data:
            issue_id = advisory.get("issue_id") or ""
            cve_id = advisory.get("cve_id") or ""

            advisory_id, aliases = parse_vuln_ids(issue_id, cve_id)

            if not advisory_id:
                self.log(
                    f"Skipping advisory with missing advisory_id. issue_id:{issue_id} cve_id:{cve_id}"
                )
                continue

            details = advisory.get("details")

            platform = advisory.get("platform")

            fixed_versions = advisory.get("fix_versions", [])

            package_name = MM_REPO.get(platform)

            affected_packages = []
            severity = advisory.get("severity")
            if not package_name:
                self.log(f"Unknown platform '{platform}' in advisory '{advisory_id}'.")

            else:
                package = PackageURL(
                    type="github",
                    namespace="mattermost",
                    name=MM_REPO.get(platform),
                )

                if isinstance(fixed_versions, list):
                    fixed_versions = [v for v in fixed_versions if v and v.strip()]
                    fixed_versions = [v.lstrip("v") for v in fixed_versions]
                if isinstance(fixed_versions, str):
                    fixed_versions = [fixed_versions.lstrip("v")]

                fixed_versions = [v.replace("and ", "") for v in fixed_versions]
                fixed_versions = [v.strip() for v in fixed_versions]

                try:
                    affected_packages.append(
                        AffectedPackageV2(
                            package=package,
                            fixed_version_range=GitHubVersionRange.from_versions(fixed_versions),
                        )
                    )
                except Exception as e:
                    self.log(
                        f"Error processing fixed versions '{fixed_versions}' for advisory '{advisory_id}': {e}"
                    )

            severities = []
            severities.append(
                VulnerabilitySeverity(system=severity_systems.CVSS31_QUALITY, value=severity)
            )

            reference = ReferenceV2(
                url="https://mattermost.com/security-updates/",
            )

            yield AdvisoryDataV2(
                advisory_id=advisory_id,
                aliases=aliases,
                summary=details,
                references=[reference],
                affected_packages=affected_packages,
                severities=severities,
                url=self.url,
                original_advisory_text=json.dumps(advisory, indent=2, ensure_ascii=False),
            )


def parse_vuln_ids(issue_id, cve_id):
    """
    Parses a raw issue_id, cve_id, validate and returns the advisory id and a list of all valid aliases.
    """
    advisory_id = None
    aliases = []

    cve_id = cve_id.strip()
    issue_id = issue_id.strip()

    for vuln_id in issue_id.split(","):
        vuln_id = vuln_id.strip()
        if vuln_id.startswith("MMSA-") or vuln_id.startswith("CVE-"):
            aliases.append(vuln_id)

    if cve_id and is_cve(cve_id):
        aliases.append(cve_id)

    if aliases:
        advisory_id = aliases.pop(0)

    return advisory_id, aliases
