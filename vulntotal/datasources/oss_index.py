#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import os
from typing import Iterable

import requests
from packageurl import PackageURL

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
            return parse_advisory(response, purl)

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


def parse_advisory(component, purl) -> Iterable[VendorData]:
    response = component[0]
    vulnerabilities = response.get("vulnerabilities") or []
    for vuln in vulnerabilities:
        aliases = [vuln["id"]]
        affected_versions = []
        fixed_versions = []
        version_ranges = vuln.get("versionRanges") or []
        affected_versions.extend(version_ranges)
        yield VendorData(
            purl=PackageURL(purl.type, purl.namespace, purl.name),
            aliases=aliases,
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
        )
