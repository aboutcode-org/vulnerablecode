#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from typing import Iterable
from typing import List
from typing import Mapping

from packageurl import PackageURL
from univers.version_range import ArchLinuxVersionRange
from univers.versions import ArchLinuxVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.utils import fetch_response


class ArchlinuxImporter(Importer):
    url = "https://security.archlinux.org/json"
    spdx_license_expression = "MIT"
    license_url = "https://github.com/archlinux/arch-security-tracker/blob/master/LICENSE"

    def fetch(self) -> Iterable[Mapping]:
        response = fetch_response(self.url)
        return response.json()

    def advisory_data(self) -> Iterable[AdvisoryData]:
        for record in self.fetch():
            yield from self.parse_advisory(record)

    def parse_advisory(self, record) -> List[AdvisoryData]:
        advisories = []
        aliases = record.get("issues") or []
        for alias in aliases:
            affected_packages = []
            for name in record["packages"]:
                summary = record.get("type") or ""
                if summary == "unknown":
                    summary = ""
                affected = record.get("affected") or ""
                affected_version_range = (
                    ArchLinuxVersionRange.from_versions([affected]) if affected else None
                )
                fixed = record.get("fixed") or ""
                fixed_version = ArchLinuxVersion(fixed) if fixed else None
                affected_packages = []
                affected_package = AffectedPackage(
                    package=PackageURL(
                        name=name,
                        type="alpm",
                        namespace="archlinux",
                    ),
                    affected_version_range=affected_version_range,
                    fixed_version=fixed_version,
                )
                affected_packages.append(affected_package)

            references = []
            references.append(
                Reference(
                    reference_id=record["name"],
                    url="https://security.archlinux.org/{}".format(record["name"]),
                    severities=[
                        VulnerabilitySeverity(
                            system=severity_systems.ARCHLINUX, value=record["severity"]
                        )
                    ],
                )
            )

            for ref in record["advisories"]:
                references.append(
                    Reference(
                        reference_id=ref,
                        url="https://security.archlinux.org/{}".format(ref),
                    )
                )

            advisories.append(
                AdvisoryData(
                    aliases=[alias],
                    summary=summary,
                    affected_packages=affected_packages,
                    references=references,
                )
            )

        return advisories
