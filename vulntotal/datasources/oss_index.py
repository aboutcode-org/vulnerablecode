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
import os
from typing import Iterable

import requests

from vulntotal.validator import DataSource
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


class OSSDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"
    api_unauthenticated = "https://ossindex.sonatype.org/api/v3/component-report"
    api_authenticated = "https://ossindex.sonatype.org/api/v3/authorized/component-report"

    def fetch_json_response(self, coordinates):
        username = os.environ.get("OSS_USERNAME", None)
        token = os.environ.get("OSS_TOKEN", None)
        auth = None
        url = self.api_unauthenticated
        if username and token:
            auth = (username, token)
            url = self.api_authenticated
        response = requests.post(url, auth=auth, json={"coordinates": coordinates})

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            logger.error("Invalid credentials")
        elif response.status_code == 429:
            msg = (
                "Too many requests"
                if auth
                else "Too many requests: add OSS_USERNAME and OSS_TOKEN in .env file"
            )
            logger.error(msg)
        else:
            logger.error(f"unknown status code: {response.status_code} while fetching: {url}")

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        if purl.type not in self.supported_ecosystem():
            logger.error("Unsupported PURL")
            return

        response = self.fetch_json_response([str(purl)])
        if response:
            self._raw_dump.append(response)
            return parse_advisory(response)

    @classmethod
    def supported_ecosystem(cls):
        return {
            "cargo": "cargo",
            "cocoapods": "cocoapods",
            "composer": "composer",
            "conan": "conan",
            "conda": "conda",
            "cran": "cran",
            "golang": "golang",
            "maven": "maven",
            "npm": "npm",
            "nuget": "nuget",
            "pypi": "pypi",
            "rpm": "rpm",
            "gem": "gem",
            "swift": "swift",
        }


def parse_advisory(component) -> Iterable[VendorData]:
    response = component[0]
    if response["vulnerabilities"]:
        for vuln in response["vulnerabilities"]:
            aliases = [vuln["id"]]
            affected_versions = []
            fixed_versions = []
            if "versionRanges" in vuln:
                affected_versions.extend(vuln["versionRanges"])
            yield VendorData(
                aliases=aliases,
                affected_versions=affected_versions,
                fixed_versions=fixed_versions,
            )
