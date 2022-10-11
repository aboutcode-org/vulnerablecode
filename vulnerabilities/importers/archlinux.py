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
from urllib.request import urlopen

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
            yield self.parse_advisory(record)

    def parse_advisory(self, record) -> List[AdvisoryData]:
        advisories = []
        # aliases = record["issues"]
        aliases = record.get("issues") or []
        # for alias in record["issues"]:
        for alias in aliases:
            affected_packages = []
            for name in record["packages"]:
                summary = record.get("type") or ""
                if summary == "unknown":
                    summary = ""

                # affected_packages = AffectedPackage(
                #     PackageURL(
                #         name=name,
                #         type="alpm",
                #         namespace="archlinux",
                #     ),
                #     affected_version_range=ArchLinuxVersionRange.from_versions(
                #         [record.get("affected") or ""]
                #     ),
                #     fixed_version=ArchLinuxVersion(record.get("fixed") or ""),
                # )
                affected = record.get("affected") or ""
                affected_version_range = (
                    ArchLinuxVersionRange.from_versions([affected]) if affected else None
                )
                fixed = record.get("fixed") or ""
                fixed_version = ArchLinuxVersion(fixed) if fixed else None
                affected_packages = AffectedPackage(
                    package=PackageURL(
                        name=name,
                        type="alpm",
                        namespace="archlinux",
                    ),
                    affected_version_range=affected_version_range,
                    fixed_version=fixed_version,
                )

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
                    aliases=[alias, record["name"]],
                    summary=summary,
                    affected_packages=affected_packages,
                    references=references,
                )
            )

        # The print statements below will print the structure of each test advisory when either of these tests is run:
        # pytest -vvs -k test_parse_advisory_single vulnerabilities/tests/test_archlinux.py
        # pytest -vvs -k test_parse_advisory_multi vulnerabilities/tests/test_archlinux.py

        print("\n\r=================================\n\r")

        for advisory in advisories:
            print(f"1. aliases: {advisory.aliases}\r\n")
            for alias in advisory.aliases:

                print("\talias: {}\r\n".format(alias))

            print(f"2. summary: {advisory.summary}\r\n")

            print(f"3. affected_packages: {advisory.affected_packages}\r\n")

            print("\tpackage: {}\r\n".format(advisory.affected_packages.package))

            print("\t\ttype: {}\r".format(advisory.affected_packages.package.type))

            print("\t\tnamespace: {}\r".format(advisory.affected_packages.package.namespace))

            print("\t\tname: {}\r".format(advisory.affected_packages.package.name))

            print("\t\tversion: {}\r".format(advisory.affected_packages.package.version))

            print("\t\tqualifiers: {}\r".format(advisory.affected_packages.package.qualifiers))

            print("\t\tsubpath: {}\r\n".format(advisory.affected_packages.package.subpath))

            print(
                "\taffected_version_range: {}\r\n".format(
                    advisory.affected_packages.affected_version_range
                )
            )

            print("\tfixed_version: {}\r\n".format(advisory.affected_packages.fixed_version))

            print(f"4. references: {advisory.references}\r")
            for ref in advisory.references:

                print("\r\nref: {}\r\n".format(ref))

                print("\treference_id: {}\r\n".format(ref.reference_id))

                print("\turl: {}\r\n".format(ref.url))

                print("\tseverities: {}\r\n".format(ref.severities))

            print(f"5. date_published: {advisory.date_published}\r")

            print("\n\r=================================\n\r")

        return advisories
