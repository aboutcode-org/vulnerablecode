#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.
from re import IGNORECASE
from typing import Any
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Set

import requests
import yaml
from bs4 import BeautifulSoup
from packageurl import PackageURL
from schema import Or
from schema import Regex
from schema import Schema

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import is_cve

BASE_URL = "https://secdb.alpinelinux.org/"


# def validate_schema(advisory_dict):
#     scheme = {
#         "distroversion": Regex(r"v\d.\d*"),
#         "reponame": str,
#         "archs": list,
#         "packages": [
#             {
#                 "pkg": {
#                     "name": str,
#                     "secfixes": {
#                         str: Or(
#                             [
#                                 Or(
#                                     Regex(r"CVE.\d+-\d+", flags=IGNORECASE),
#                                     Regex(r"XSA-\d{3}"),
#                                     Regex(r"ZBX-\d{4}"),
#                                     Regex(r"wnpa-sec-\d{4}-\d{2}"),
#                                     Regex(r"GHSA-.{4}-.{4}-.{4}"),
#                                 )
#                             ],
#                             "",
#                             # FIXME: Remove the None when below issue gets fixed
#                             # https://gitlab.alpinelinux.org/alpine/infra/alpine-secdb/-/issues/1
#                             None,
#                         ),
#                     },
#                 }
#             }
#         ],
#         object: object,
#     }
#     Schema(scheme).validate(advisory_dict)


class AlpineDataSource(DataSource):
    @staticmethod
    def fetch_advisory_links():
        index_page = BeautifulSoup(requests.get(BASE_URL).content, features="lxml")

        alpine_versions = [
            link.text for link in index_page.find_all("a") if link.text.startswith("v")
        ]

        advisory_directory_links = [f"{BASE_URL}{version}" for version in alpine_versions]

        advisory_links = []
        for advisory_directory_link in advisory_directory_links:
            advisory_directory_page = requests.get(advisory_directory_link).content
            advisory_directory_page = BeautifulSoup(advisory_directory_page, features="lxml")
            advisory_links.extend(
                [
                    f"{advisory_directory_link}{anchore_tag.text}"
                    for anchore_tag in advisory_directory_page.find_all("a")
                    if anchore_tag.text.endswith("yaml")
                ]
            )

        return advisory_links

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []
        advisory_links = self.fetch_advisory_links()
        for link in advisory_links:
            advisories.extend(self._process_link(link))

        return self.batch_advisories(advisories)

    def _process_link(self, link) -> List[Advisory]:
        advisories = []
        yaml_response = requests.get(link).content
        record = yaml.safe_load(yaml_response)

        if record["packages"] is None:
            return advisories

        for p in record["packages"]:
            advisories.extend(
                self._load_advisories(
                    p["pkg"],
                    record["distroversion"],
                    record["reponame"],
                    record["archs"],
                )
            )

        return advisories

    def _load_advisories(
        self,
        pkg_infos: Mapping[str, Any],
        distroversion: str,
        reponame: str,
        archs: Iterable[str],
    ) -> List[Advisory]:

        advisories = []

        for version, fixed_vulns in pkg_infos["secfixes"].items():

            if fixed_vulns is None:
                continue

            resolved_purls = {
                PackageURL(
                    name=pkg_infos["name"],
                    type="alpine",
                    version=version,
                    qualifiers={"arch": arch, "distroversion": distroversion, "reponame": reponame},
                )
                for arch in archs
            }

            for vuln_ids in fixed_vulns:
                vuln_ids = vuln_ids.split()
                references = []
                for reference_id in vuln_ids[1:]:

                    if reference_id.startswith("XSA"):
                        xsa_id = reference_id.split("-")[-1]
                        references.append(
                            Reference(
                                reference_id=reference_id,
                                url="https://xenbits.xen.org/xsa/advisory-{}.html".format(xsa_id),
                            )
                        )

                    elif reference_id.startswith("ZBX"):
                        references.append(
                            Reference(
                                reference_id=reference_id,
                                url="https://support.zabbix.com/browse/{}".format(reference_id),
                            )
                        )

                    elif reference_id.startswith("wnpa-sec"):
                        references.append(
                            Reference(
                                reference_id=reference_id,
                                url="https://www.wireshark.org/security/{}.html".format(
                                    reference_id
                                ),
                            )
                        )

                # TODO: Handle the CVE-????-????? case
                advisories.append(
                    Advisory(
                        summary="",
                        impacted_package_urls=[],
                        resolved_package_urls=resolved_purls,
                        references=references,
                        vulnerability_id=vuln_ids[0] if is_cve(vuln_ids[0]) else "",
                    )
                )

        return advisories
