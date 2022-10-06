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

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import nearest_patched_package


class ArchlinuxImporter(Importer):
    url = "https://security.archlinux.org/json"
    spdx_license_expression = "unknown"

    def fetch(self) -> Iterable[Mapping]:
        response = fetch_response(self.url)
        return response.json()

    def advisory_data(self) -> Iterable[AdvisoryData]:
        for record in self.fetch():
            yield self.parse_advisory(record)

    # The JSON includes 'status' and 'type' fields do we want to incorporate them into the AdvisoryData objects?
    # Although not directly reflected in the JSON, the web page for at least some references include an additional reference,
    # see, e.g., https://security.archlinux.org/AVG-2781 (one of our test inputs, which lists this ref: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24)
    # Do we want to incorporate them into the AdvisoryData objects?
    def parse_advisory(self, record) -> List[AdvisoryData]:
        advisories = []
        aliases = record["issues"]
        for alias in record["issues"]:
            affected_packages = []
            for name in record["packages"]:
                impacted_purls, resolved_purls = [], []
                impacted_purls.append(
                    PackageURL(
                        name=name,
                        type="alpm",
                        namespace="archlinux",
                        version=record["affected"],
                    )
                )

                if record["fixed"]:
                    resolved_purls.append(
                        PackageURL(
                            name=name,
                            type="alpm",
                            namespace="archlinux",
                            version=record["fixed"],
                        )
                    )
                affected_packages.extend(nearest_patched_package(impacted_purls, resolved_purls))

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
                    # Do we want/need to keep this inside a list?  "aliases" is plural but I understand we want to break out each alias individually.
                    # However, it looks like alpine_linux.py and nginx.py, for example, return a list of aliases.
                    aliases=[alias],
                    # aliases=alias,
                    summary="",
                    affected_packages=affected_packages,
                    references=references,
                )
            )

        # The print statements below will print the structure of each test advisory when either of these tests is run:
        # pytest -vvs -k test_parse_advisory_single vulnerabilities/tests/test_archlinux.py
        # pytest -vvs -k test_parse_advisory_multi vulnerabilities/tests/test_archlinux.py

        print("\n\r=================================\n\r")

        for advisory in advisories:
            print(f"1. aliases: {advisory.aliases}\r")
            print("")
            print(f"2. summary: {advisory.summary}\r")
            print("")
            print(f"3. affected_packages: {advisory.affected_packages}\r")
            for pkg in advisory.affected_packages:
                print("")
                print("vulnerable_package: {}\r".format(pkg.vulnerable_package))
                print("")
                print("patched_package: {}\r".format(pkg.patched_package))
            print("")
            print(f"4. references: {advisory.references}\r")
            for ref in advisory.references:
                print("")
                print("ref: {}\r".format(ref))
            print("")
            print(f"5. date_published: {advisory.date_published}\r")
            print("\n\r=================================\n\r")

        return advisories
