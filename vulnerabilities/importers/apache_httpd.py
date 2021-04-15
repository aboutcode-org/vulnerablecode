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

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems
from vulnerabilities.helpers import create_etag


@dataclasses.dataclass
class ApacheHTTPDDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


class ApacheHTTPDDataSource(DataSource):

    CONFIG_CLASS = ApacheHTTPDDataSourceConfiguration
    url = "https://httpd.apache.org/security/json/{}"
    ref_url = "https://httpd.apache.org/security/json/{}.json"

    def updated_advisories(self):
        # Etags are like hashes of web responses. We maintain
        # (url, etag) mappings in the DB. `create_etag`  creates
        # (url, etag) pair. If a (url, etag) already exists then the code
        # skips processing the response further to avoid duplicate work

        if create_etag(data_src=self, url=self.url, etag_key="ETag"):
            links = fetch_links(self.url)
            advisories = []
            for link in links:
                data = requests.get(link).json()
                advisories.append(self.to_advisory(data))
            return self.batch_advisories(advisories)

        return []

    def to_advisory(self, data):
        cve = data["CVE_data_meta"]["ID"]
        descriptions = data.get("description", {}).get("description_data", [])
        description = None
        for desc in descriptions:
            if desc.get("lang") == "eng":
                description = desc.get("value")
                break

        impacts = data.get("impact", [])
        impact = None
        for imp in impacts:
            value = imp.get("other")
            if value is not None:
                impact = value
                break

        if impact is not None:
            severity = VulnerabilitySeverity(
                system=scoring_systems["apache_httpd"],
                value=impact,
            )
            reference = Reference(
                reference_id=cve,
                url=self.ref_url.format(cve),
                severities=[severity],
            )
        else:
            reference = Reference(
                reference_id=cve,
                url=self.ref_url.format(cve),
            )

        resolved_packages = []
        impacted_packages = []

        for vendor in data["affects"]["vendor"]["vendor_data"]:
            for products in vendor["product"]["product_data"]:
                for version in products["version"]["version_data"]:
                    version_value = version["version_value"]

                    if version["version_affected"] == "<":
                        resolved_packages.append(
                            PackageURL(type="apache", name="httpd", version=version_value)
                        )

                    else:
                        impacted_packages.append(
                            PackageURL(type="apache", name="httpd", version=version_value)
                        )

        return Advisory(
            vulnerability_id=cve,
            summary=description,
            impacted_package_urls=impacted_packages,
            resolved_package_urls=resolved_packages,
            references=[reference],
        )


def fetch_links(url):
    links = []
    data = requests.get(url.format("")).content
    soup = BeautifulSoup(data, features="lxml")
    for tag in soup.find_all("a"):
        link = tag.get("href")
        if not link.endswith("json"):
            continue
        links.append(url.format(link))
    return links
