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

from dataclasses import dataclass
from xml.etree import ElementTree

import requests
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration


@dataclass
class ApacheHTTPDDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


class ApacheHTTPDDataSource(DataSource):

    CONFIG_CLASS = ApacheHTTPDDataSourceConfiguration
    url = "https://httpd.apache.org/security/vulnerabilities-httpd.xml"

    def updated_advisories(self):
        # Etags are like hashes of web responses. We maintain
        # (url, etag) mappings in the DB. `create_etag`  creates
        # (url, etag) pair. If a (url, etag) already exists then the code
        # skips processing the response further to avoid duplicate work

        if self.create_etag(self.url):
            data = fetch_xml(self.url)
            advisories = to_advisories(data)
            return self.batch_advisories(advisories)

        return []

    def create_etag(self, url):
        etag = requests.head(url).headers.get("ETag")
        if not etag:
            return True

        elif url in self.config.etags:
            if self.config.etags[url] == etag:
                return False

        self.config.etags[url] = etag
        return True


def to_advisories(data):
    advisories = []
    for issue in data:
        resolved_packages = []
        impacted_packages = []
        for info in issue:
            if info.tag == "cve":
                cve = info.attrib["name"]

            if info.tag == "title":
                summary = info.text

            if info.tag == "fixed":
                resolved_packages.append(
                    PackageURL(type="apache", name="httpd", version=info.attrib["version"])
                )

            if info.tag == "affects" or info.tag == "maybeaffects":
                impacted_packages.append(
                    PackageURL(type="apache", name="httpd", version=info.attrib["version"])
                )

        advisories.append(
            Advisory(
                cve_id=cve,
                summary=summary,
                impacted_package_urls=impacted_packages,
                resolved_package_urls=resolved_packages,
            )
        )

    return advisories


def fetch_xml(url):
    resp = requests.get(url).content
    return ElementTree.fromstring(resp)
