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
from urllib.parse import quote

import requests
from packageurl import PackageURL

from vulntotal.validator import DataSource
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


class DepsDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"

    def fetch_json_response(self, url):
        response = requests.get(url)
        if not response.status_code == 200 or response.text == "Not Found":
            logger.error(f"Error while fetching {url}")
            return
        return response.json()

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        payload = generate_meta_payload(purl)
        response = self.fetch_json_response(payload)
        if response:
            advisories = parse_advisories_from_meta(response)
            if advisories:
                for advisory in advisories:
                    advisory_payload = generate_advisory_payload(advisory)
                    fetched_advisory = self.fetch_json_response(advisory_payload)
                    self._raw_dump.append(fetched_advisory)
                    if fetched_advisory:
                        return parse_advisory(fetched_advisory)

    @classmethod
    def supported_ecosystem(cls):
        return {
            "npm": "npm",
            "maven": "maven",
            "golang": "go",
            "pypi": "pypi",
            "cargo": "cargo",
            # Coming soon
            # "nuget": "nuget",
        }


def parse_advisory(advisory) -> Iterable[VendorData]:
    affected_versions = [event["version"] for event in advisory["packages"][0]["versionsAffected"]]
    fixed_versions = [event["version"] for event in advisory["packages"][0]["versionsUnaffected"]]
    yield VendorData(
        aliases=sorted(list(set(advisory["aliases"]))),
        affected_versions=sorted(list(set(affected_versions))),
        fixed_versions=sorted(list(set(fixed_versions))),
    )


def parse_advisories_from_meta(advisories_metadata):
    advisories = []
    if "dependencies" in advisories_metadata and advisories_metadata["dependencies"]:
        for dependency in advisories_metadata["dependencies"]:
            if dependency["advisories"]:
                advisories.extend(dependency["advisories"])
    return advisories


def generate_advisory_payload(advisory_meta):
    url_advisory = "https://deps.dev/_/advisory/{source}/{sourceID}"
    return url_advisory.format(source=advisory_meta["source"], sourceID=advisory_meta["sourceID"])


def generate_meta_payload(purl):
    url_advisories_meta = "https://deps.dev/_/s/{ecosystem}/p/{package}/v/{version}/dependencies"
    supported_ecosystem = DepsDataSource.supported_ecosystem()
    if purl.type in supported_ecosystem:
        purl_version = purl.version
        purl_name = purl.name

        if purl.type == "maven":
            if not purl.namespace:
                logger.error(f"Invalid Maven PURL {str(purl)}")
                return
            purl_name = quote(f"{purl.namespace}:{purl.name}", safe="")

        elif purl.type == "golang":
            if purl.namespace:
                purl_name = quote(f"{purl.namespace}/{purl.name}", safe="")
            if not purl_version.startswith("v"):
                purl_version = f"v{purl_version}"

        return url_advisories_meta.format(
            ecosystem=supported_ecosystem[purl.type],
            package=purl_name,
            version=purl_version,
        )
