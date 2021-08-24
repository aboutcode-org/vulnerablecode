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
from dateutil import parser as dateparser
from typing import Any
from typing import List
from typing import Mapping
from typing import Set

import requests
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import nearest_patched_package


@dataclasses.dataclass
class DebianConfiguration(DataSourceConfiguration):
    debian_tracker_url: str


class DebianDataSource(DataSource):

    CONFIG_CLASS = DebianConfiguration

    def __enter__(self):
        if self.response_is_new():
            self._api_response = self._fetch()

        else:
            self._api_response = {}

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []

        for pkg_name, records in self._api_response.items():
            advisories.extend(self._parse(pkg_name, records))

        return self.batch_advisories(advisories)

    def _fetch(self) -> Mapping[str, Any]:
        return requests.get(self.config.debian_tracker_url).json()

    def _parse(self, pkg_name: str, records: Mapping[str, Any]) -> List[Advisory]:
        advisories = []
        ignored_versions = {"3.8.20-4."}

        for cve_id, record in records.items():
            impacted_purls, resolved_purls = [], []
            if not cve_id.startswith("CVE"):
                continue

            # vulnerabilities starting with something else may not be public yet
            # see for instance https://web.archive.org/web/20201215213725/https://security-tracker.debian.org/tracker/TEMP-0000000-A2EB44
            # TODO: this would need to be revisited though to ensure we are not missing out on anything

            for release_name, release_record in record["releases"].items():
                if not release_record.get("repositories", {}).get(release_name):
                    continue

                version = release_record["repositories"][release_name]

                if version in ignored_versions:
                    continue

                purl = PackageURL(
                    name=pkg_name,
                    type="deb",
                    namespace="debian",
                    version=version,
                    qualifiers={"distro": release_name},
                )

                if release_record.get("status", "") == "resolved":
                    resolved_purls.append(purl)
                else:
                    impacted_purls.append(purl)

                if (
                    "fixed_version" in release_record
                    and release_record["fixed_version"] not in ignored_versions
                ):
                    resolved_purls.append(
                        PackageURL(
                            name=pkg_name,
                            type="deb",
                            namespace="debian",
                            version=release_record["fixed_version"],
                            qualifiers={"distro": release_name},
                        )
                    )

            references = []
            debianbug = record.get("debianbug")
            if debianbug:
                bug_url = f"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={debianbug}"
                references.append(Reference(url=bug_url, reference_id=debianbug))
            advisories.append(
                Advisory(
                    vulnerability_id=cve_id,
                    affected_packages=nearest_patched_package(impacted_purls, resolved_purls),
                    summary=record.get("description", ""),
                    references=references,
                )
            )

        return advisories

    def response_is_new(self):
        """
        Return True if a request response is for new data likely changed or
        updated since we last checked.
        """
        head = requests.head(self.config.debian_tracker_url)
        date_str = head.headers.get("last-modified")
        last_modified_date = dateparser.parse(date_str)
        print('last_modified_date:', type(last_modified_date), last_modified_date)
        print('self.config.last_run_date:', type(self.config.last_run_date), self.config.last_run_date)
        if self.config.last_run_date:
            return self.config.last_run_date < last_modified_date

        return True
