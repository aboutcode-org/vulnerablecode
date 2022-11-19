#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnTotal software is licensed under the Apache License version 2.0.
# Data generated with VulnTotal require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnTotal or any VulnTotal
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnTotal and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnTotal should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnTotal is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json
import logging
from typing import Iterable
from urllib.parse import urljoin

import requests
from packageurl import PackageURL

from vulntotal.validator import DataSource
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


class VulnerableCodeDataSource(DataSource):
    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://github.com/nexB/vulnerablecode/blob/main/cc-by-sa-4.0.LICENSE"

    global_instance = None
    vc_purl_search_api_path = "api/packages/bulk_search/"

    def fetch_post_json(self, payload):
        vc_instance = self.global_instance if self.global_instance else "http://localhost:8001/"

        url = urljoin(vc_instance, self.vc_purl_search_api_path)
        response = requests.post(url, json=payload)
        if not response.status_code == 200:
            logger.error(f"Error while fetching {url}")
            return
        return response.json()

    def fetch_get_json(self, url):
        response = requests.get(url)
        if not response.status_code == 200:
            logger.error(f"Error while fetching {url}")
            return
        return response.json()

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        if purl.type not in self.supported_ecosystem() or not purl.version:
            return
        metadata_advisories = self.fetch_post_json({"purls": [str(purl)]})
        self._raw_dump.append(metadata_advisories)
        if metadata_advisories and "affected_by_vulnerabilities" in metadata_advisories[0]:
            for advisory in metadata_advisories[0]["affected_by_vulnerabilities"]:
                fetched_advisory = self.fetch_get_json(advisory["url"])
                self._raw_dump.append(fetched_advisory)
                yield parse_advisory(fetched_advisory)

    @classmethod
    def supported_ecosystem(cls):
        return {
            "alpine": "alpine",
            "cargo": "cargo",
            "composer": "composer",
            "deb": "deb",
            "golang": "golang",
            "maven": "maven",
            "nginx": "nginx",
            "npm": "npm",
            "nuget": "nuget",
            "pypi": "pypi",
            "rpm": "rpm",
            "gem": "gem",
            "openssl": "openssl",
        }


def parse_advisory(fetched_advisory) -> VendorData:
    aliases = [aliase["alias"] for aliase in fetched_advisory["aliases"]]
    affected_versions = []
    fixed_versions = []
    for instance in fetched_advisory["affected_packages"]:
        affected_versions.append(PackageURL.from_string(instance["purl"]).version)
    for instance in fetched_advisory["fixed_packages"]:
        fixed_versions.append(PackageURL.from_string(instance["purl"]).version)
    return VendorData(
        aliases=aliases, affected_versions=affected_versions, fixed_versions=fixed_versions
    )
