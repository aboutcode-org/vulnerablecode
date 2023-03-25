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
from bs4 import BeautifulSoup

from vulntotal.validator import DataSource
from vulntotal.validator import VendorData
from vulntotal.vulntotal_utils import snyk_constraints_satisfied

logger = logging.getLogger(__name__)


class SnykDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"

    def fetch(self, url):
        """Fetch the content of a given URL.

        Args:
            url: A string containing the URL to fetch.

        Returns:
            A string of HTML or a dictionary of JSON if the response is successful,
            or None if the response is unsuccessful.
        """
        response = requests.get(url)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Error while fetching {url}: {e}")
            return
        if response.headers["content-type"] == "application/json, charset=utf-8":
            return response.json()
        return response.text

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        """Fetch advisories from Snyk for a given package.

        Args:
            purl: A PackageURL object representing the package.

        Returns:
            An iterable of VendorData objects containing advisory information.
        """
        package_advisory_url = generate_package_advisory_url(purl)
        package_advisories_list = self.fetch(package_advisory_url)
        self._raw_dump.append(package_advisories_list)
        if package_advisories_list:
            advisories = extract_html_json_advisories(package_advisories_list)
            for snyk_id, affected in advisories.items():
                if "*" in affected or is_purl_in_affected(purl.version, affected):
                    advisory_payload = generate_advisory_payload(snyk_id)
                    advisory_html = self.fetch(advisory_payload)
                    self._raw_dump.append(advisory_html)
                    if advisory_html:
                        yield parse_html_advisory(advisory_html, snyk_id, affected)

    @classmethod
    def supported_ecosystem(cls):
        return {
            "cocoapods": "cocoapods",
            "composer": "composer",
            "golang": "golang",
            "hex": "hex",
            "linux": "linux",
            "maven": "maven",
            "npm": "npm",
            "nuget": "nuget",
            "pypi": "pip",
            "rubygems": "rubygems",
            # any purl.type not in supported_ecosystem shall implicitly be treated as unmanaged type
            "unmanaged": "unmanaged",
        }


def generate_package_advisory_url(purl):
    """Generate a URL for fetching advisories from Snyk for a given package.

    Args:
        purl: A PackageURL object representing the package.

    Returns:
        A string containing the URL or None if the package is not supported.
    """
    url_package_advisories = "https://security.snyk.io/package/{ecosystem}/{package}"

    # Pseudo API, unfortunately gives only 30 vulnerability per package, but this is the best we have for unmanaged packages
    url_unmanaged_package_advisories = (
        "https://security.snyk.io/api/listing?search={package}&type=unmanaged"
    )
    supported_ecosystem = SnykDataSource.supported_ecosystem()

    if purl.type == "unmanaged" or purl.type not in supported_ecosystem:
        return url_unmanaged_package_advisories.format(
            package=purl.name if not purl.namespace else f"{purl.namespace}/{purl.name}",
        )

    purl_name = purl.name
    if purl.type == "maven":
        if not purl.namespace:
            logger.error(f"Invalid Maven PURL {str(purl)}")
            return
        purl_name = quote(f"{purl.namespace}:{purl.name}", safe="")

    elif purl.type in ("golang", "composer"):
        if purl.namespace:
            purl_name = quote(f"{purl.namespace}/{purl.name}", safe="")

    elif purl.type == "linux":
        distro = purl.qualifiers["distro"]
        purl_name = f"{distro}/{purl.name}"

    return url_package_advisories.format(
        ecosystem=supported_ecosystem[purl.type],
        package=purl_name,
    )


def extract_html_json_advisories(package_advisories):
    """Extract vulnerability information from HTML or JSON advisories.

    Args:
        package_advisories: A string of HTML or a dictionary of JSON containing
            advisories for a package.

    Returns:
        A dictionary mapping vulnerability IDs to lists of affected versions.
    """
    vulnerability = {}

    # If advisories are json and is obtained through pseudo API
    if isinstance(package_advisories, dict):
        if package_advisories["status"] == "ok":
            for vuln in package_advisories["vulnerabilities"]:
                vulnerability[vuln["id"]] = vuln["semver"]["vulnerable"]
    else:
        soup = BeautifulSoup(package_advisories, "html.parser")
        vulns_table = soup.find("tbody", class_="vue--table__tbody")
        if vulns_table:
            vulns_rows = vulns_table.find_all("tr", class_="vue--table__row")
            for row in vulns_rows:
                anchor = row.find(class_="vue--anchor")
                ranges = row.find_all(
                    "span", class_="vue--chip vulnerable-versions__chip vue--chip--default"
                )
                affected_versions = [vers.text.strip() for vers in ranges]
                vulnerability[anchor["href"].rsplit("/", 1)[-1]] = affected_versions
    return vulnerability


def parse_html_advisory(advisory_html, snyk_id, affected) -> VendorData:
    """Parse HTML advisory from Snyk and extract vendor data.

    Args:
        advisory_html: A string of HTML containing the advisory details.
        snyk_id: A string containing the Snyk ID of the vulnerability.
        affected: A list of strings containing the affected versions.

    Returns:
        A VendorData object containing aliases, affected versions and fixed versions.
    """
    aliases = []
    fixed_versions = []

    advisory_soup = BeautifulSoup(advisory_html, "html.parser")
    cve_span = advisory_soup.find("span", class_="cve")
    if cve_span:
        cve_anchor = cve_span.find("a", class_="vue--anchor")
        aliases.append(cve_anchor["id"])

    how_to_fix = advisory_soup.find(
        "div", class_="vue--block vuln-page__instruction-block vue--block--instruction"
    )
    if how_to_fix:
        fixed = how_to_fix.find("p").text.split(" ")
        if "Upgrade" in fixed:
            lower = fixed.index("version") if "version" in fixed else fixed.index("versions")
            upper = fixed.index("or")
            fixed_versions = [ver.strip(",") for ver in fixed[lower + 1 : upper]]
    aliases.append(snyk_id)
    return VendorData(
        aliases=aliases,
        affected_versions=affected,
        fixed_versions=fixed_versions,
    )


def is_purl_in_affected(version, affected):
    return any(snyk_constraints_satisfied(affected_range, version) for affected_range in affected)


def generate_advisory_payload(snyk_id):
    return f"https://security.snyk.io/vuln/{snyk_id}"
