#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Iterable
from typing import List

import requests
from packageurl import PackageURL

from vulntotal.validator import DataSource
from vulntotal.validator import InvalidCVEError
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


class SafetydbDataSource(DataSource):
    spdx_license_expression = "CC-BY-NC-4.0"
    license_url = "https://github.com/pyupio/safety-db/blob/master/LICENSE.txt"
    url = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"

    def fetch_advisory(self):
        """
        Fetch entire JSON advisory from pyupio repository

        Parameters:

        Returns:
            A JSON object containing the advisory information for insecure packages, or None if an error occurs while fetching data from safetydb repo's URL.
        """

        response = requests.get(self.url)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Error while fetching safetydb advisories: {e}")
            return

        return response.json()

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        if purl.type not in self.supported_ecosystem():
            return []
        advisory = self.fetch_advisory()
        self._raw_dump.append(advisory)
        return parse_advisory(advisory, purl)

    def datasource_advisory_from_cve(self, cve: str) -> Iterable[VendorData]:
        if not cve.upper().startswith("CVE-"):
            raise InvalidCVEError
        advisory = self.fetch_advisory()
        self._raw_dump.append(advisory)
        return parse_advisory_for_cve(advisory, cve)

    @classmethod
    def supported_ecosystem(cls):
        return {"pypi": "PyPI"}


def parse_advisory(response, purl: PackageURL) -> Iterable[VendorData]:
    """
    Parse response from safetydb API and yield VendorData

    Parameters:
        response: A JSON object containing the response data from the safetydb datasource.

    Yields:
        VendorData instance containing the advisory information for the package.
    """

    for advisory in response.get(purl.name, []):
        yield VendorData(
            purl=PackageURL(purl.type, purl.namespace, purl.name),
            aliases=[advisory.get("cve"), advisory.get("id")],
            affected_versions=sorted(advisory.get("specs")),
            fixed_versions=[],
        )


def parse_advisory_for_cve(response, cve: str) -> Iterable[VendorData]:
    """
    Parse response from safetydb API and yield VendorData with specified CVE

    Parameters:
        response: A JSON object containing the response data from the safetydb datasource.

    Yields:
        VendorData instance containing the advisory information for the package.
    """

    for package, advisories in response.items():
        if package == "$meta":
            continue

        for advisory in advisories:
            if advisory.get("cve") == cve:
                yield VendorData(
                    purl=PackageURL(type="pypi", name=package),
                    aliases=[advisory.get("cve"), advisory.get("id")],
                    affected_versions=sorted(advisory.get("specs")),
                    fixed_versions=[],
                )
