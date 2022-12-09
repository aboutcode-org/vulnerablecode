#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# Author: Navonil Das (@NavonilDas)

from pathlib import Path
from typing import Iterable
from typing import List

import pytz
from dateutil.parser import parse
from packageurl import PackageURL
from univers.version_range import NpmVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.utils import build_description
from vulnerabilities.utils import load_json


class NpmImporter(Importer):
    spdx_license_expression = "MIT"
    license_url = "https://github.com/nodejs/security-wg/blob/main/LICENSE.md"
    repo_url = "git+https://github.com/nodejs/security-wg"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone(self.repo_url)
            path = Path(self.vcs_response.dest_dir)

            vuln = path / "vuln"
            npm_vulns = vuln / "npm"
            for file in npm_vulns.glob("*.json"):
                yield from self.to_advisory_data(file)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def to_advisory_data(self, file: Path) -> List[AdvisoryData]:
        data = load_json(file)
        id = data.get("id")
        description = data.get("overview") or ""
        summary = data.get("title") or ""
        date_published = parse(data.get("created_at")).replace(tzinfo=pytz.UTC)
        references = []
        cvss_vector = data.get("cvss_vector")
        cvss_score = data.get("cvss_score")
        severities = []
        if cvss_vector and cvss_vector.startswith("CVSS:3.0/"):
            severities.append(
                VulnerabilitySeverity(
                    system=CVSSV3,
                    value=cvss_score,
                )
            )
        if cvss_vector and cvss_vector.startswith("CVSS:2.0/"):
            severities.append(
                VulnerabilitySeverity(
                    system=CVSSV2,
                    value=cvss_score,
                )
            )

        advisory_reference = Reference(
            url=f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json",
            reference_id=id,
            severities=severities,
        )

        for ref in data.get("references") or []:
            references.append(
                Reference(
                    url=ref,
                    severities=severities,
                )
            )

        if advisory_reference not in references:
            references.append(advisory_reference)

        package_name = data.get("module_name")
        affected_packages = []
        if package_name:
            affected_packages.append(self.get_affected_package(data, package_name))
        advsisory_aliases = data.get("cves") or []

        for alias in advsisory_aliases:
            yield AdvisoryData(
                summary=build_description(summary=summary, description=description),
                references=references,
                date_published=date_published,
                affected_packages=affected_packages,
                aliases=[alias],
            )

    def get_affected_package(self, data, package_name):
        affected_version_range = None
        unaffected_version_range = None
        fixed_version = None

        vulnerable_range = data.get("vulnerable_versions") or ""
        patched_range = data.get("patched_versions") or ""

        # https://github.com/nodejs/security-wg/blob/cfaa51cc5c83f01eea61b69658f7bc76a77c5979/vuln/npm/213.json#L14
        if vulnerable_range == "<=99.999.99999":
            vulnerable_range = "*"
        if vulnerable_range:
            affected_version_range = NpmVersionRange.from_native(vulnerable_range)

        # https://github.com/nodejs/security-wg/blob/cfaa51cc5c83f01eea61b69658f7bc76a77c5979/vuln/npm/213.json#L15
        if patched_range == "<0.0.0":
            patched_range = None
        if patched_range:
            unaffected_version_range = NpmVersionRange.from_native(patched_range)

        # We only store single fixed versions and not a range of fixed versions
        # If there is a single constraint in the unaffected_version_range
        # having comparator as ">=" then we store that as the fixed version
        if unaffected_version_range and len(unaffected_version_range.constraints) == 1:
            constraint = unaffected_version_range.constraints[0]
            if constraint.comparator == ">=":
                fixed_version = constraint.version

        return AffectedPackage(
            package=PackageURL(
                type="npm",
                name=package_name,
            ),
            affected_version_range=affected_version_range,
            fixed_version=fixed_version,
        )
