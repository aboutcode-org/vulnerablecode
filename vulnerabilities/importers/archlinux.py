#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import dataclasses
import json
import pprint
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Set
from urllib.request import urlopen

from packageurl import PackageURL

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity

# 9/28/2022 Wednesday 12:58:46 PM.  Do we need the next import?  It's used at the bottom!
from vulnerabilities.models import Advisory

# 9/28/2022 Wednesday 1:04:27 PM.  From /home/jmh/dev/nexb/vulnerablecode/vulnerabilities/importers/alpine_linux.py
# copy fetch_response function to vulnerabilities.utils then import here and use below
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import nearest_patched_package

# Take a URL -> Grab the data from the URL -> Map it according to AdvisoryData


class ArchlinuxImporter(Importer):
    # def __enter__(self):
    #     self._api_response = self._fetch()

    # def updated_advisories(self) -> Set[AdvisoryData]:
    #     advisories = []

    #     for record in self._api_response:
    #         advisories.extend(self._parse(record))

    #     return self.batch_advisories(advisories)

    # def _fetch(self) -> Iterable[Mapping]:
    #     with urlopen(self.config.archlinux_tracker_url) as response:
    #         return json.load(response)

    url = "https://security.archlinux.org/json"
    spdx_license_expression = "unknown"

    def fetch(self) -> Iterable[Mapping]:
        response = fetch_response(self.url)
        return response.json()

    def advisory_data(self) -> Iterable[AdvisoryData]:
        for record in self.fetch():
            yield self.parse_advisory(record)

    # def _parse(self, record) -> List[AdvisoryData]:
    def parse_advisory(self, record) -> List[AdvisoryData]:
        advisories = []
        aliases = record["issues"]
        for cve_id in record["issues"]:
            affected_packages = []
            for name in record["packages"]:
                impacted_purls, resolved_purls = [], []
                impacted_purls.append(
                    PackageURL(
                        name=name,
                        # type="pacman",
                        # type="alpm",
                        type="archlinux",
                        namespace="archlinux",
                        version=record["affected"],
                    )
                )

                if record["fixed"]:
                    resolved_purls.append(
                        PackageURL(
                            name=name,
                            # type="pacman",
                            # type="alpm",
                            type="archlinux",
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
                # Advisory(
                AdvisoryData(
                    # deprecated
                    # vulnerability_id=cve_id,
                    aliases=[cve_id],
                    # summary="",
                    affected_packages=affected_packages,
                    references=references,
                )
            )

        print("\rHello World!\r")

        print("\radvisories = {}\r".format(advisories))

        for apple in advisories:
            # pprint.pprint(apple.to_dict())
            print(apple.affected_packages)
            print(f"aliases: {apple.aliases}")
            print(f"summary: {apple.summary}")
            print(f"affected_packages: {apple.affected_packages}")

        return advisories
