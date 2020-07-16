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

from typing import Set

from packageurl import PackageURL
import requests
import re

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import VulnerabilityReferenceUnit

import xml.etree.ElementTree as ET


class OpenSSLDataSource(DataSource):
    def updated_advisories(self) -> Set[Advisory]:
        raw_data = self.fetch()
        advisories = self.to_advisories(raw_data)
        return self.batch_advisories(advisories)

    def fetch(self):
        return requests.get("https://www.openssl.org/news/vulnerabilities.xml").content

    @staticmethod
    def to_advisories(xml_response: str) -> Set[Advisory]:
        advisories = []
        pkg_name = "openssl"
        pkg_type = "generic"
        root = ET.fromstring(xml_response)
        for element in root:
            if element.tag == "issue":
                cve_id = ''
                summary = ''
                safe_pkg_versions = []
                vuln_pkg_versions = []
                ref_urls = []
                for info in element:

                    if info.tag == 'cve':
                        cve_id = 'CVE-' + info.attrib.get('name')

                    if info.tag == 'affects':
                        # Vulnerable package versions
                        vuln_pkg_versions.append(info.attrib.get('version'))

                    if info.tag == 'fixed':
                        # Fixed package versions
                        safe_pkg_versions.append(info.attrib.get('version'))

                        if info:
                            commit_hash = info[0].attrib['hash']
                            ref_urls.append(VulnerabilityReferenceUnit(url="https://github.com/openssl/openssl/commit/"
                                            + commit_hash))
                    if info.tag == 'description':
                        # Description
                        summary = re.sub(r'\s+', ' ', info.text).strip()

                safe_purls = {PackageURL(name=pkg_name,
                                         type=pkg_type,
                                         version=version)
                              for version in safe_pkg_versions}
                vuln_purls = {PackageURL(name=pkg_name,
                                         type=pkg_type,
                                         version=version)
                              for version in vuln_pkg_versions}

                advisory = Advisory(cve_id=cve_id,
                                    summary=summary,
                                    impacted_package_urls=vuln_purls,
                                    resolved_package_urls=safe_purls,
                                    vuln_references=ref_urls)
                advisories.append(advisory)

        return advisories
