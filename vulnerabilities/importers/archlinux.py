#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.
import dataclasses
import json
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Set
from urllib.request import urlopen

from packageurl import PackageURL

from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.severity_systems import scoring_systems


class ArchlinuxImporter(Importer):
    def __enter__(self):
        self._api_response = self._fetch()

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []

        for record in self._api_response:
            advisories.extend(self._parse(record))

        return self.batch_advisories(advisories)

    def _fetch(self) -> Iterable[Mapping]:
        with urlopen(self.config.archlinux_tracker_url) as response:
            return json.load(response)

    def _parse(self, record) -> List[Advisory]:
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
                            system=scoring_systems["avgs"], value=record["severity"]
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
