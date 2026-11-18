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
from dotenv import load_dotenv
from packageurl import PackageURL

from vulntotal.validator import DataSource
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


class SonatypeGuideDataSource(DataSource):
    """
    Datasource for Sonatype Guide (formerly OSS Index).

    Authentication:
        Configure your Sonatype Guide Personal Access Token (PAT) in the
        environment or ``.env`` file::

            SONATYPE_GUIDE_TOKEN="your-sonatype-guide-pat"

        When authenticating with a PAT, the username is optional and automatically
        defaults to ``"token"``, so users do not need to invent or provide a username.
        An explicit username can optionally be configured via ``SONATYPE_GUIDE_USERNAME``::

            SONATYPE_GUIDE_USERNAME="user@example.com"
            SONATYPE_GUIDE_TOKEN="your-sonatype-guide-pat"

        Legacy ``OSS_TOKEN`` and ``OSS_USERNAME`` environment variables are also
        supported for backward compatibility.
    """

    spdx_license_expression = "TODO"
    license_url = "TODO"
    api_unauthenticated = "https://api.guide.sonatype.com/api/v3/component-report"
    api_authenticated = "https://api.guide.sonatype.com/api/v3/authorized/component-report"

    def fetch_json_response(self, coordinates):
        """Fetch JSON response from Sonatype Guide API for a given list of coordinates.

        Authentication uses ``SONATYPE_GUIDE_TOKEN`` (or legacy ``OSS_TOKEN``).
        When only ``SONATYPE_GUIDE_TOKEN`` is set, username defaults to ``"token"``,
        so users only need to provide their PAT without inventing a username.

        Parameters:
            coordinates: A list of strings representing the package coordinates.

        Returns:
            A dictionary containing the JSON response from the Sonatype Guide API,
            or None if the response is unsuccessful or an error occurs while fetching data.
        """
        load_dotenv()
        token = os.environ.get("SONATYPE_GUIDE_TOKEN") or os.environ.get("OSS_TOKEN")
        username = (
            os.environ.get("SONATYPE_GUIDE_USERNAME")
            or os.environ.get("OSS_USERNAME")
            or ("token" if token else None)
        )
        auth = None
        url = self.api_unauthenticated
        if token:
            auth = (username, token)
            url = self.api_authenticated
        response = requests.post(url, auth=auth, json={"coordinates": coordinates})
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                logger.error("Invalid credentials")
            elif e.response.status_code == 429:
                msg = (
                    "Too many requests"
                    if auth
                    else "Too many requests: add SONATYPE_GUIDE_TOKEN (or legacy OSS_TOKEN) in .env file"
                )
                logger.error(msg)
            else:
                logger.error(f"Unknown status code: {e.response.status_code} while fetching: {url}")

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


# Maintain backward compatibility for existing imports and usages
OSSDataSource = SonatypeGuideDataSource


def parse_advisory(component, purl) -> Iterable[VendorData]:
    """
    Parse component from OSS Index API and yield VendorData.

    Parameters:
        component: A list containing a dictionary with component details.
        purl: PURL for the advisory.

    Yields:
        VendorData instance containing advisory information for the component.
    """
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
