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
from vulnerabilities.utils import nearest_patched_package


class ArchlinuxImporter(Importer):
    def __enter__(self):
        self._api_response = self._fetch()

    def updated_advisories(self) -> Set[AdvisoryData]:
        advisories = []

        for record in self._api_response:
            advisories.extend(self._parse(record))

        return self.batch_advisories(advisories)

    def _fetch(self) -> Iterable[Mapping]:
        with urlopen(self.config.archlinux_tracker_url) as response:
            return json.load(response)

    def _parse(self, record) -> List[AdvisoryData]:
        advisories = []

        for cve_id in record["issues"]:
            affected_packages = []
            for name in record["packages"]:
                impacted_purls, resolved_purls = [], []
                impacted_purls.append(
                    PackageURL(
                        name=name,
                        type="pacman",
                        namespace="archlinux",
                        version=record["affected"],
                    )
                )

                if record["fixed"]:
                    resolved_purls.append(
                        PackageURL(
                            name=name,
                            type="pacman",
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
                Advisory(
                    vulnerability_id=cve_id,
                    summary="",
                    affected_packages=affected_packages,
                    references=references,
                )
            )

        return advisories
