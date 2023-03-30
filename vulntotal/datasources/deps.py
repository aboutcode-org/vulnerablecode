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
from urllib.parse import quote

import requests

from vulntotal.validator import DataSource
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


class DepsDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"

    def fetch_json_response(self, url):
        response = requests.get(url)
        if response.status_code != 200 or response.text == "Not Found":
            logger.error(f"Error while fetching {url}")
            return
        return response.json()

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        """
        Fetch and parse advisories from a given purl.

        Parameters:
            purl: A string representing the package URL.

        Returns:
            A list of VendorData objects containing the advisory information.
        """
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
    """
    Parse an advisory into a VendorData object.

    Parameters:
        advisory: A dictionary representing the advisory data.

    Yields:
        VendorData instance containing purl, aliases, affected_versions and fixed_versions.
    """
    package = advisory["packages"][0]
    affected_versions = [event["version"] for event in package["versionsAffected"]]
    fixed_versions = [event["version"] for event in package["versionsUnaffected"]]
    yield VendorData(
        aliases=sorted(set(advisory["aliases"])),
        affected_versions=sorted(set(affected_versions)),
        fixed_versions=sorted(set(fixed_versions)),
    )


def parse_advisories_from_meta(advisories_metadata):
    """
    Parse advisories from a given metadata.

    Parameters:
        advisories_metadata: A dictionary representing the metadata of the advisories.

    Returns:
        A list of dictionaries, each representing an advisory.
    """
    advisories = []
    dependencies = advisories_metadata.get("dependencies") or []
    for dependency in dependencies:
        advs = dependency.get("advisories") or []
        advisories.extend(advs)
    return advisories


def generate_advisory_payload(advisory_meta):
    url_advisory = "https://deps.dev/_/advisory/{source}/{sourceID}"
    return url_advisory.format(source=advisory_meta["source"], sourceID=advisory_meta["sourceID"])


def generate_meta_payload(purl):
    """
    Generate a payload for fetching advisories metadata from a given purl.

    Parameters:
        purl: A PackageURL object representing the package URL.

    Returns:
        A string representing the payload for fetching advisories metadata. It should be a valid URL that contains the ecosystem, package name and package version of the dependency.
    """
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
