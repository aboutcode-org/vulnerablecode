#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from typing import Iterable
from urllib.parse import quote
from urllib.parse import unquote_plus

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulntotal.validator import DataSource
from vulntotal.validator import InvalidCVEError
from vulntotal.validator import VendorData
from vulntotal.vulntotal_utils import snyk_constraints_satisfied

logger = logging.getLogger(__name__)

fixed_version_pattern = re.compile(r"\b\d[\w.-]*\b")


class SnykDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"

    def fetch(self, url):
        """
        Fetch the content of a given URL.

        Parameters:
            url: A string representing the URL to fetch.

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
        """
        Fetch advisories from Snyk for a given package.

        Parameters:
            purl: A PackageURL instance representing the package.

        Yields:
            VendorData instance containing advisory information.
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
                        yield parse_html_advisory(advisory_html, snyk_id, affected, purl)

    def datasource_advisory_from_cve(self, cve: str) -> Iterable[VendorData]:
        """
        Fetch advisories from Snyk for a given CVE.

        Parameters:
            cve : CVE ID

        Yields:
            VendorData instance containing advisory information.
        """
        if not cve.upper().startswith("CVE-"):
            raise InvalidCVEError

        package_list = generate_payload_from_cve(cve)
        response = self.fetch(package_list)
        self._raw_dump = [response]

        # get list of vulnerabilities for cve id
        vulns_list = parse_cve_advisory_html(response)

        # for each vulnerability get fixed version from snyk_id_url, get affected version from package_advisory_url
        for snyk_id, package_advisory_url in vulns_list.items():
            package_advisories_list = self.fetch(package_advisory_url)
            package_advisories = extract_html_json_advisories(package_advisories_list)
            affected_versions = package_advisories[snyk_id]
            advisory_payload = generate_advisory_payload(snyk_id)
            advisory_html = self.fetch(advisory_payload)
            self._raw_dump.append(advisory_html)
            purl = generate_purl(package_advisory_url)
            if advisory_html and purl:
                yield parse_html_advisory(advisory_html, snyk_id, affected_versions, purl)

    @classmethod
    def supported_ecosystem(cls):
        return {
            "cargo": "cargo",
            "cocoapods": "cocoapods",
            "composer": "composer",
            "golang": "golang",
            "hex": "hex",
            "linux": "linux",
            "maven": "maven",
            "npm": "npm",
            "nuget": "nuget",
            "pub": "pub",
            "pypi": "pip",
            "gem": "rubygems",
            # any purl.type not in supported_ecosystem shall implicitly be treated as unmanaged type
            "unmanaged": "unmanaged",
        }


def generate_package_advisory_url(purl):
    """
    Generate a URL for fetching advisories from Snyk for a given package.

    Parameters:
        purl: A PackageURL instance representing the package.

    Returns:
        A string containing the URL or None if the package is not supported by Snyk.
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


def generate_purl(package_advisory_url):
    """
    Generates purl from Package advisory url.

    Parameters:
        package_advisory_url: URL of the package on Snyk.

    Returns:
        A PackageURL instance representing the package
    """
    package_advisory_url = unquote_plus(
        package_advisory_url.replace("https://security.snyk.io/package/", "")
    )
    supported_ecosystems = {v: k for (k, v) in SnykDataSource.supported_ecosystem().items()}

    package_url_split = package_advisory_url.split("/")
    pkg_type = package_url_split[0]

    pkg_name = None
    namespace = None
    qualifiers = {}

    if pkg_type == "maven":
        pkg_name = package_url_split[1].split(":")[1]
        namespace = package_url_split[1].split(":")[0]

    elif pkg_type == "composer":
        pkg_name = package_url_split[-1]
        namespace = package_url_split[-2]

    elif pkg_type == "golang":
        pkg_name = package_url_split[-1]
        namespace = "/".join(package_url_split[1:-1])

    elif pkg_type == "npm":
        # handle scoped npm packages
        if "@" in package_advisory_url:
            namespace = package_url_split[-2]

        pkg_name = package_url_split[-1]

    elif pkg_type == "linux":
        pkg_name = package_url_split[-1]
        qualifiers["distro"] = package_url_split[1]

    elif pkg_type in ("cocoapods", "hex", "nuget", "pip", "rubygems", "unmanaged"):
        pkg_name = package_url_split[-1]

    if pkg_type is None or pkg_name is None:
        logger.error("Invalid package advisory url, package type or name is missing")
        return

    return PackageURL(type=supported_ecosystems[pkg_type], name=pkg_name, namespace=namespace)


def extract_html_json_advisories(package_advisories):
    """
    Extract vulnerability information from HTML or JSON advisories.

    Parameters:
        package_advisories: A string of HTML or a dictionary of JSON containing advisories for a package.

    Returns:
        A dictionary mapping vulnerability IDs to lists of affected versions for the package.
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


def parse_html_advisory(advisory_html, snyk_id, affected, purl) -> VendorData:
    """
    Parse HTML advisory from Snyk and extract vendor data.

    Parameters:
        advisory_html: A string of HTML containing the advisory details.
        snyk_id: A string representing the Snyk ID of the vulnerability.
        affected: A list of strings representing the affected versions.
        purl: PURL for the advisory.

    Returns:
        A VendorData instance containing aliases, affected versions and fixed versions for the vulnerability.
    """
    aliases = []
    fixed_versions = []

    advisory_soup = BeautifulSoup(advisory_html, "html.parser")
    cve_span = advisory_soup.find("span", class_="cve")
    if cve_span:
        if cve_anchor := cve_span.find("a", class_="vue--anchor"):
            aliases.append(cve_anchor.get("id"))

    how_to_fix = advisory_soup.find(
        "div", class_="vue--block vuln-page__instruction-block vue--block--instruction"
    )

    if how_to_fix and (fixed := how_to_fix.find("p").text):
        fixed_versions = fixed_version_pattern.findall(fixed)

    aliases.append(snyk_id)
    return VendorData(
        purl=PackageURL(purl.type, purl.namespace, purl.name),
        aliases=aliases,
        affected_versions=affected,
        fixed_versions=fixed_versions,
    )


def parse_cve_advisory_html(cve_advisory_html):
    """
    Parse CVE HTML advisory from Snyk and extract list of vulnerabilities and corresponding packages for that CVE.

    Parameters:
        advisory_html: A string of HTML containing the vulnerabilities for given CVE.

    Returns:
        A dictionary with each item representing a vulnerability. Key of each item is the SNYK_ID and value is the package advisory url on snyk website
    """
    cve_advisory_soup = BeautifulSoup(cve_advisory_html, "html.parser")
    vulns_table = cve_advisory_soup.find("tbody", class_="vue--table__tbody")
    if not vulns_table:
        return None
    vulns_rows = vulns_table.find_all("tr", class_="vue--table__row")
    vulns_list = {}

    for row in vulns_rows:
        anchors = row.find_all("a", {"class": "vue--anchor"})
        if len(anchors) != 2:
            continue
        snyk_id = anchors[0]["href"].split("/")[1]
        package_advisory_url = f"https://security.snyk.io{anchors[1]['href']}"
        vulns_list[snyk_id] = package_advisory_url

    return vulns_list


def is_purl_in_affected(version, affected):
    return any(snyk_constraints_satisfied(affected_range, version) for affected_range in affected)


def generate_advisory_payload(snyk_id):
    return f"https://security.snyk.io/vuln/{snyk_id}"


def generate_payload_from_cve(cve_id):
    return f"https://security.snyk.io/vuln?search={cve_id}"
