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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import dataclasses
import re
from typing import Set
import xml.etree.ElementTree as ET

from packageurl import PackageURL
import requests

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.helpers import create_etag
from vulnerabilities.helpers import nearest_patched_package


@dataclasses.dataclass
class OpenSSLDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


class OpenSSLDataSource(DataSource):
    CONFIG_CLASS = OpenSSLDataSourceConfiguration

    url = "https://www.openssl.org/news/vulnerabilities.xml"

    def updated_advisories(self) -> Set[Advisory]:
        # Etags are like hashes of web responses. We maintain
        # (url, etag) mappings in the DB. `create_etag`  creates
        # (url, etag) pair. If a (url, etag) already exists then the code
        # skips processing the response further to avoid duplicate work
        if create_etag(data_src=self, url=self.url, etag_key="ETag"):
            raw_data = self.fetch()
            advisories = self.to_advisories(raw_data)
            return self.batch_advisories(advisories)

        return []

    def fetch(self):
        return requests.get(self.url).content

    @staticmethod
    def to_advisories(xml_response: str) -> Set[Advisory]:
        advisories = []
        pkg_name = "openssl"
        pkg_type = "generic"
        root = ET.fromstring(xml_response)
        for element in root:
            if element.tag == "issue":
                cve_id = ""
                summary = ""
                safe_pkg_versions = []
                vuln_pkg_versions = []
                ref_urls = []
                for info in element:

                    if info.tag == "cve":
                        if info.attrib.get("name"):
                            cve_id = "CVE-" + info.attrib.get("name")

                        else:
                            continue

                    if cve_id == "CVE-2007-5502":
                        # This CVE has weird version "fips-1.1.2".This is
                        # probably a submodule. Skip this for now.
                        continue

                    if info.tag == "affects":
                        # Vulnerable package versions
                        vuln_pkg_versions.append(info.attrib.get("version"))

                    if info.tag == "fixed":
                        # Fixed package versions
                        safe_pkg_versions.append(info.attrib.get("version"))

                        if info:
                            commit_hash = info[0].attrib["hash"]
                            ref_urls.append(
                                Reference(
                                    url="https://github.com/openssl/openssl/commit/" + commit_hash
                                )
                            )
                    if info.tag == "description":
                        # Description
                        summary = re.sub(r"\s+", " ", info.text).strip()

                safe_purls = [
                    PackageURL(name=pkg_name, type=pkg_type, version=version)
                    for version in safe_pkg_versions
                ]
                vuln_purls = [
                    PackageURL(name=pkg_name, type=pkg_type, version=version)
                    for version in vuln_pkg_versions
                ]

                advisory = Advisory(
                    vulnerability_id=cve_id,
                    summary=summary,
                    affected_packages=nearest_patched_package(vuln_purls, safe_purls),
                    references=ref_urls,
                )
                advisories.append(advisory)

        return advisories
