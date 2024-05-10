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
from fetchcode.package_versions import versions
from packageurl import PackageURL
from univers.version_range import PypiVersionRange
from univers.versions import PypiVersion

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
        if purl.type != "pypi":
            return []
        advisory = self.fetch_advisory()
        self._raw_dump.append(advisory)
        self._versions = sorted([PypiVersion(ver.value) for ver in versions(str(purl))])
        return parse_advisory(advisory, purl, self._versions)

    def datasource_advisory_from_cve(self, cve: str) -> Iterable[VendorData]:
        if not cve.upper().startswith("CVE-"):
            raise InvalidCVEError
        advisory = self.fetch_advisory()
        self._raw_dump.append(advisory)
        return parse_advisory_for_cve(advisory, cve)

    @classmethod
    def supported_ecosystem(cls):
        # source - @TODO
        return {"pypi": "PyPI"}


def parse_advisory(
    response, purl: PackageURL, all_versions: List[PypiVersion]
) -> Iterable[VendorData]:
    """
    Parse response from safetydb API and yield VendorData

    Parameters:
        response: A JSON object containing the response data from the safetydb datasource.

    Yields:
        VendorData instance containing the advisory information for the package.
    """

    for advisory in response.get(purl.name):
        vulnerable_version_range_string = "vers:pypi/" + advisory.get("v").replace(",", "|")
        vulnerable_version_range = PypiVersionRange.from_string(vulnerable_version_range_string)

        yield VendorData(
            purl=PackageURL(purl.type, purl.namespace, purl.name),
            aliases=[advisory.get("cve"), advisory.get("id")],
            affected_versions=sorted(advisory.get("specs")),
            fixed_versions=get_patched_versions(all_versions, vulnerable_version_range),
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

        all_versions = sorted(
            [PypiVersion(ver.value) for ver in versions(str(PackageURL(type="pypi", name=package)))]
        )

        for advisory in advisories:
            if advisory.get("cve") == cve:
                vulnerable_version_range_string = "vers:pypi/" + advisory.get("v").replace(",", "|")
                vulnerable_version_range = PypiVersionRange.from_string(
                    vulnerable_version_range_string
                )

                yield VendorData(
                    purl=PackageURL(type="pypi", name=package),
                    aliases=[advisory.get("cve"), advisory.get("id")],
                    affected_versions=sorted(advisory.get("specs")),
                    fixed_versions=get_patched_versions(all_versions, vulnerable_version_range),
                )


def get_patched_versions(
    all_versions: List[PypiVersion],
    vulnerable_version_range: PypiVersionRange,
):
    """
    Get the first patched version from the list of all versions of a package

    Parameters:
        all_versions: A list containing PackageVersion of a package
        vulnerable_version_range: A PypiVersionRange object specifying the vulnerable version range

    Returns:
        A PackageVersion object containing the first patched version of the package
    """

    # last_patched = None
    # for version in reversed(all_versions):
    #     if version in vulnerable_version_range:
    #         if last_patched is not None:
    #             return [str(last_patched.value)]
    #         return []
    #     last_patched = version
    # return []

    patched_version_ranges: List[str] = []
    current_patched_range_start: PypiVersion = None
    current_patched_range_latest: PypiVersion = None

    def resolve_patched_range():
        if current_patched_range_start is not None:
            if current_patched_range_latest == current_patched_range_start:
                patched_version_ranges.append(str(current_patched_range_start.value))
            else:
                patched_version_ranges.append(
                    f">={current_patched_range_start.value},<={current_patched_range_latest.value}"
                )

    for version in all_versions:
        if version in vulnerable_version_range:
            resolve_patched_range()
            current_patched_range_start = None
            current_patched_range_latest = None
        else:
            if current_patched_range_start is None:
                current_patched_range_start = version
            current_patched_range_latest = version
    resolve_patched_range()

    # Remove upper bound from the last fixed range
    if len(patched_version_ranges) > 0:
        patched_version_ranges[-1] = patched_version_ranges[-1].split(",")[0]

    # Ensure that >= is only present if there are fragmented fixed ranges
    # eg. For vulnerable spec  "<2.2.5 >=2.3.0 <2.3.2",,fixed range => "2.2.5, >=2.3.2"
    # eg. For vulnerable spec "<2.2.5", fixed range => "2.2.5
    if len(patched_version_ranges) == 1:
        patched_version_ranges[-1] = patched_version_ranges[-1][2:]

    return patched_version_ranges
