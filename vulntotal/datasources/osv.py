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

import requests

from vulntotal.ecosystem.nuget import search_closest_nuget_package_name
from vulntotal.validator import DataSource
from vulntotal.validator import VendorData
from vulntotal.vulntotal_utils import get_item

logger = logging.getLogger(__name__)


class OSVDataSource(DataSource):
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/google/osv/blob/master/LICENSE"
    url = "https://api.osv.dev/v1/query"

    def fetch_advisory(self, payload):
        """
        Fetch JSON advisory from OSV API for a given package payload

        Parameters:
            payload: A dictionary representing the package data to query.

        Returns:
            A JSON object containing the advisory information for the package, or None if an error occurs while fetching data from the OSV API.
        """

        response = requests.post(self.url, data=str(payload))
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Error while fetching {payload}: {e}")
            return
        return response.json()

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        payload = generate_payload(purl)
        if not payload:
            return
        advisory = self.fetch_advisory(payload)
        self._raw_dump.append(advisory)
        return parse_advisory(advisory)

    @classmethod
    def supported_ecosystem(cls):
        # source https://ossf.github.io/osv-schema/
        return {
            "npm": "npm",
            "maven": "Maven",
            "golang": "Go",
            "nuget": "NuGet",
            "pypi": "PyPI",
            "rubygems": "RubyGems",
            "crates.io": "crates.io",
            "composer": "Packagist",
            "linux": "Linux",
            "oss-fuzz": "OSS-Fuzz",
            "debian": "Debian",
            "hex": "Hex",
            "android": "Android",
        }


def parse_advisory(response) -> Iterable[VendorData]:
    """
    Parse response from OSV API and yield VendorData

    Parameters:
        response: A JSON object containing the response data from the OSV API.

    Yields:
        VendorData instance containing the advisory information for the package.
    """

    for vuln in response.get("vulns") or []:
        aliases = []
        affected_versions = []
        fixed = []

        aliases.extend(vuln.get("aliases") or [])
        vuln_id = vuln.get("id")
        aliases.append(vuln_id) if vuln_id else None

        try:
            affected_versions.extend(get_item(vuln, "affected", 0, "versions") or [])
        except KeyError as e:
            logger.error(f"Error while parsing affected versions: {e}")

        try:
            events = get_item(vuln, "affected", 0, "ranges", 0, "events") or []
            affected_versions.extend(
                [event.get("introduced") for event in events if event.get("introduced")]
            )
            fixed.extend([event.get("fixed") for event in events if event.get("fixed")])
        except KeyError as e:
            logger.error(f"Error while parsing events: {e}")

        yield VendorData(
            aliases=sorted(list(set(aliases))),
            affected_versions=sorted(list(set(affected_versions))),
            fixed_versions=sorted(list(set(fixed))),
        )


def generate_payload(purl):
    """
    Generate compatible payload for OSV API from a PURL

    Parameters:
        purl: A PackageURL instance representing the package to query.

    Returns:
        A dictionary containing the package data compatible with the OSV API.
    """

    supported_ecosystem = OSVDataSource.supported_ecosystem()
    payload = {}
    payload["version"] = purl.version
    package = payload["package"] = {}

    purl_type = purl.type
    purl_namespace = purl.namespace

    if purl_type in supported_ecosystem:
        package["ecosystem"] = supported_ecosystem[purl_type]

    if purl_type == "maven":
        if not purl_namespace:
            logger.error(f"Invalid Maven PURL {str(purl)}")
            return
        package["name"] = f"{purl.namespace}:{purl.name}"

    elif purl_type == "packagist":
        if not purl_namespace:
            logger.error(f"Invalid Packagist PURL {str(purl)}")
            return
        package["name"] = f"{purl.namespace}/{purl.name}"

    elif purl_type == "linux":
        if purl.name not in ("kernel", "Kernel"):
            logger.error(f"Invalid Linux PURL {str(purl)}")
            return
        package["name"] = "Kernel"

    elif purl_type == "nuget":
        nuget_package = search_closest_nuget_package_name(purl.name)
        if not nuget_package:
            logger.error(f"Invalid NuGet PURL {str(purl)}")
            return
        package["name"] = nuget_package

    elif purl_type == "golang" and purl_namespace:
        package["name"] = f"{purl.namespace}/{purl.name}"

    else:
        package["name"] = purl.name

    return payload
