# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import bz2
import dataclasses
import json

import requests
from packageurl import PackageURL

from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference


@dataclasses.dataclass
class USNDBConfiguration:
    etags: list
    db_url: str


class UbuntuUSNDataSource(DataSource):
    CONFIG_CLASS = USNDBConfiguration

    def updated_advisories(self):
        advisories = []
        if self.create_etag(self.config.db_url):
            advisories.extend(self.to_advisories(fetch(self.config.db_url)))

        return self.batch_advisories(advisories)

    def create_etag(self, url):
        etag = requests.head(url).headers.get("etag")
        if not etag:
            return True

        elif url in self.config.etags:
            if self.config.etags[url] == etag:
                return False

        self.config.etags[url] = etag
        return True

    @staticmethod
    def to_advisories(usn_db):
        advisories = []
        for usn in usn_db:
            reference = get_usn_references(usn_db[usn]["id"])
            for release in usn_db[usn]["releases"]:
                pkg_dict = usn_db[usn]["releases"][release]
                safe_purls = get_purls(pkg_dict)

            for cve in usn_db[usn].get("cves", [""]):
                # The db sometimes contains entries like
                # {'cves': ['python-pgsql vulnerabilities', 'CVE-2006-2313', 'CVE-2006-2314']}
                # This `if` filters entries like 'python-pgsql vulnerabilities'
                if not cve.startswith("CVE-"):
                    continue

                advisories.append(
                    Advisory(
                        cve_id=cve,
                        impacted_package_urls=[],
                        resolved_package_urls=safe_purls,
                        summary="",
                        vuln_references=[reference],
                    )
                )

        return advisories


def get_usn_references(usn_id):
    return Reference(
        reference_id="USN-" + usn_id, url="https://usn.ubuntu.com/{}/".format(usn_id)
    )


def fetch(url):
    response = requests.get(url).content
    raw_data = bz2.decompress(response)

    return json.loads(raw_data)


def get_purls(pkg_dict):
    purls = set()
    for pkg_name in pkg_dict.get("sources", []):
        version = pkg_dict["sources"][pkg_name]["version"]
        # The db sometimes contains entries like {'postgresql': {'version': ''}}
        # This `if` ignores such entries
        if not version:
            continue

        purls.add(PackageURL(name=pkg_name, version=version, type="deb", namespace="ubuntu",))

    for pkg_name in pkg_dict["binaries"]:
        version = pkg_dict["binaries"][pkg_name]["version"]
        # The db sometimes contains entries like {'postgresql': {'version': ''}}
        # This `if` ignores such entries
        if not version:
            continue

        purls.add(PackageURL(name=pkg_name, version=version, type="deb", namespace="ubuntu",))
    return purls
