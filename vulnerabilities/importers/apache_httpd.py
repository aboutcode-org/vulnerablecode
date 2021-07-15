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

import asyncio
import dataclasses
import urllib

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.versions import MavenVersion
from univers.version_specifier import VersionSpecifier

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.severity_systems import scoring_systems
from vulnerabilities.helpers import nearest_patched_package


@dataclasses.dataclass
class ApacheHTTPDDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


class ApacheHTTPDDataSource(DataSource):

    CONFIG_CLASS = ApacheHTTPDDataSourceConfiguration
    base_url = "https://httpd.apache.org/security/json/"

    def set_api(self):
        self.version_api = GitHubTagsAPI()
        asyncio.run(self.version_api.load_api(["apache/httpd"]))

    def updated_advisories(self):
        links = fetch_links(self.base_url)
        self.set_api()
        advisories = []
        for link in links:
            data = requests.get(link).json()
            advisories.append(self.to_advisory(data))
        return self.batch_advisories(advisories)

    def to_advisory(self, data):
        cve = data["CVE_data_meta"]["ID"]
        descriptions = data["description"]["description_data"]
        description = None
        for desc in descriptions:
            if desc["lang"] == "eng":
                description = desc.get("value")
                break

        severities = []
        impacts = data.get("impact", [])
        for impact in impacts:
            value = impact.get("other")
            if value:
                severities.append(
                    VulnerabilitySeverity(
                        system=scoring_systems["apache_httpd"],
                        value=value,
                    )
                )
                break
        reference = Reference(
            reference_id=cve,
            url=urllib.parse.urljoin(self.base_url, f"{cve}.json"),
            severities=severities,
        )

        versions_data = []
        for vendor in data["affects"]["vendor"]["vendor_data"]:
            for products in vendor["product"]["product_data"]:
                for version_data in products["version"]["version_data"]:
                    versions_data.append(version_data)

        fixed_version_ranges, affected_version_ranges = self.to_version_ranges(versions_data)

        affected_packages = []
        fixed_packages = []

        for version_range in fixed_version_ranges:
            fixed_packages.extend(
                [
                    PackageURL(type="apache", name="httpd", version=version)
                    for version in self.version_api.get("apache/httpd").valid_versions
                    if MavenVersion(version) in version_range
                ]
            )

        for version_range in affected_version_ranges:
            affected_packages.extend(
                [
                    PackageURL(type="apache", name="httpd", version=version)
                    for version in self.version_api.get("apache/httpd").valid_versions
                    if MavenVersion(version) in version_range
                ]
            )

        return Advisory(
            vulnerability_id=cve,
            summary=description,
            affected_packages=nearest_patched_package(affected_packages, fixed_packages),
            references=[reference],
        )

    def to_version_ranges(self, versions_data):
        fixed_version_ranges = []
        affected_version_ranges = []
        for version_data in versions_data:
            version_value = version_data["version_value"]
            range_expression = version_data["version_affected"]
            if range_expression == "<":
                fixed_version_ranges.append(
                    VersionSpecifier.from_scheme_version_spec_string(
                        "maven", ">={}".format(version_value)
                    )
                )
            elif range_expression == "=" or range_expression == "?=":
                affected_version_ranges.append(
                    VersionSpecifier.from_scheme_version_spec_string(
                        "maven", "{}".format(version_value)
                    )
                )

        return (fixed_version_ranges, affected_version_ranges)


def fetch_links(url):
    links = []
    data = requests.get(url).content
    soup = BeautifulSoup(data, features="lxml")
    for tag in soup.find_all("a"):
        link = tag.get("href")
        if not link.endswith("json"):
            continue
        links.append(urllib.parse.urljoin(url, link))
    return links
