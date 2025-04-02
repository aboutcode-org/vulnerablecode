#
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from typing import Any
from typing import Iterable
from typing import List
from typing import Optional

import pytz
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.versions import RpmVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.rpm_utils import rpm_to_purl
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import is_cve

LOGGER = logging.getLogger(__name__)
BASE_URL = "https://alas.aws.amazon.com/"


class AmazonLinuxImporter(Importer):
    spdx_license_expression = "CC BY 4.0"
    license_url = " "  # TODO

    importer_name = "Amazon Linux Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        amazon_linux_1_url = BASE_URL + "/index.html"
        amazon_linux_2_url = BASE_URL + "/alas2.html"
        amazon_linux_2023_url = BASE_URL + "/alas2023.html"
        amazonlinux_advisories_pages = [
            amazon_linux_1_url,
            amazon_linux_2_url,
            amazon_linux_2023_url,
        ]
        alas_dict = {}
        for amazonlinux_advisories_page in amazonlinux_advisories_pages:
            alas_dict.update(fetch_alas_id_and_advisory_links(amazonlinux_advisories_page))

        for alas_id, alas_url in alas_dict.items():
            # It iterates through alas_dict to get alas ids and alas url
            if alas_id and alas_url:
                alas_advisory_page_content = fetch_response(alas_url).content
                yield process_advisory_data(alas_id, alas_advisory_page_content, alas_url)


def fetch_alas_id_and_advisory_links(page_url: str) -> dict[str, str]:
    """
    Return a dictionary where 'ALAS' entries are the keys and
    their corresponding advisory page links are the values.
    """

    page_response_content = fetch_response(page_url).content
    # Parse the HTML content
    soup = BeautifulSoup(page_response_content, "html.parser")
    alas_dict = {}

    if page_url == "https://alas.aws.amazon.com/index.html":
        # Find all relevant ALAS links and their IDs
        for row in soup.find_all("tr", id=True):
            alas_id = row["id"]
            link_tag = row.find("a", href=True)
            if link_tag:
                full_url = "https://alas.aws.amazon.com/" + link_tag["href"]
                alas_dict[alas_id] = full_url

    elif page_url == "https://alas.aws.amazon.com/alas2.html":
        # Find all relevant ALAS links and their IDs
        for row in soup.find_all("tr", id=True):
            alas_id = row["id"]
            link_tag = row.find("a", href=True)
            if link_tag:
                full_url = "https://alas.aws.amazon.com/AL2" + link_tag["href"]
                alas_dict[alas_id] = full_url

    else:
        # Find all relevant ALAS links and their IDs
        for row in soup.find_all("tr", id=True):
            alas_id = row["id"]
            link_tag = row.find("a", href=True)
            if link_tag:
                full_url = "https://alas.aws.amazon.com/AL2023/" + link_tag["href"]
                alas_dict[alas_id] = full_url
    return alas_dict


def process_advisory_data(alas_id, alas_advisory_page_content, alas_url) -> Optional[AdvisoryData]:

    """
    Processes an Amazon Linux Security Advisory HTML page to extract relevant data and return it in a structured format.

    Args:
        alas_id (str): The unique identifier for the Amazon Linux Security Advisory (e.g., "ALAS-2024-2628").
        alas_advisory_page_content (str): The HTML content of the advisory page.
        alas_url (str): The URL of the advisory page.

    Returns:
        Optional[AdvisoryData]: An object containing the processed advisory data, or None if the necessary data couldn't be extracted.
    """

    soup = BeautifulSoup(alas_advisory_page_content, "html.parser")
    aliases = []
    aliases.append(alas_id)

    # Find the advisory release date
    release_date_span = next(
        (
            span
            for span in soup.find_all("span", class_="alas-info")
            if "Advisory Release Date:" in span.get_text(strip=True)
        ),
        None,
    )

    release_date = (
        release_date_span.get_text(strip=True).split(":", 1)[1].strip()
        if release_date_span
        else None
    )
    date_published = get_date_published(release_date)

    # Extract Issue Overview (all points of issue overviews texts)
    issue_overview = []
    for p in soup.find("div", id="issue_overview").find_all("p"):
        # Replace <br> tags with a newline, then split the text
        text_parts = p.decode_contents().split("<br/>")

        # Clean and append each part
        for part in text_parts:
            clean_text = part.strip()
            if clean_text:  # Avoid adding empty strings
                issue_overview.append(clean_text)
    # Filter out any blank entries from the list
    issue_overview_filtered = [item for item in issue_overview if item]

    summary = create_summary(issue_overview_filtered)

    # Extract Affected Packages (list of strings)
    processed_affected_packages = []
    affected_packages_section = soup.find("div", id="affected_packages")
    if affected_packages_section:
        affected_packages = affected_packages_section.find_all("p")
        affected_packages = [pkg.text.strip() for pkg in affected_packages]

    # getting new packages
    new_packages_div = soup.find("div", id="new_packages")

    # Extract the text elements between <br /> tags within this div
    if new_packages_div:
        new_packages_list = [
            element.strip() for element in new_packages_div.pre.stripped_strings if element.strip()
        ]
    else:
        new_packages_list = []

    exclude_items = ["i686:", "noarch:", "src:", "x86_64:", "aarch64:"]
    filtered_new_packages_list = [
        package for package in new_packages_list if package not in exclude_items
    ]

    # new packages are the fixed packages
    for new_package in filtered_new_packages_list:
        new_package_purl = rpm_to_purl(new_package, "alas.aws.amazon")
        if new_package_purl:
            try:
                processed_affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(
                            type="rpm",
                            namespace="alas.aws.amazon",
                            name=new_package_purl.name,
                            qualifiers=new_package_purl.qualifiers,
                            subpath=new_package_purl.subpath,
                        ),
                        affected_version_range=None,
                        fixed_version=RpmVersion(new_package_purl.version),
                    )
                )
            except ValueError as e:
                logging.error(
                    f"Invalid RPM version '{new_package_purl.version}' for package '{new_package_purl.name}': {e}"
                )

    cve_list = []
    for link in soup.find("div", id="references").find_all("a", href=True):
        if "CVE-" in link.text:
            cve_list.append((link.text.strip(), "https://alas.aws.amazon.com" + link["href"]))

    references: List[Reference] = []
    for cve_id, cve_url in cve_list:
        aliases.append(cve_id)
        cve_json_url = f"https://explore.alas.aws.amazon.com/{cve_id}.json"
        response = fetch_response(cve_json_url)

        # Parse the JSON data
        cve_info = response.json()
        severity_scores = cve_info.get("scores", [])
        severity = []
        for score in severity_scores:
            severity.append(
                VulnerabilitySeverity(
                    system=SCORING_SYSTEMS[score.get("type", "").lower()],
                    value=score.get("score", ""),
                    scoring_elements=score.get("vector", ""),
                )
            )
        references.append(Reference(reference_id=cve_id, url=cve_url, severities=severity))

    additional_references = []
    # Find all <p> tags within the links-container div
    links_container = soup.find("div", class_="links-container")
    if links_container:
        p_tags = links_container.find_all("p")
        for p_tag in p_tags:
            a_tag = p_tag.find("a")
            if a_tag:
                cve_id = a_tag.get_text(strip=True)  # Extract the CVE ID text
                url = a_tag["href"]  # Extract the URL from href attribute
                additional_references.append((cve_id, url))
    for cve_id, ref_link in additional_references:
        references.append(Reference(reference_id=cve_id, url=ref_link, severities=[]))

    url = alas_url

    return AdvisoryData(
        aliases=aliases,
        date_published=date_published,
        summary=summary,
        references=references,
        affected_packages=processed_affected_packages,
        url=url,
    )


def get_date_published(release_date_string):

    # Parse the date and time
    if release_date_string:
        date_part = release_date_string[:16]
        time_zone = release_date_string[17:]
    else:
        return None

    # Convert to datetime object (naive)
    naive_date = datetime.strptime(date_part, "%Y-%m-%d %H:%M")

    # Convert to aware datetime by adding the Pacific time zone
    timezone = pytz.timezone("America/Los_Angeles")
    date_published = timezone.localize(naive_date)
    return date_published


def create_summary(summary_point: List):
    summary = ". ".join(summary_point)
    # Add a period at the end if the final sentence doesn't end with one
    if not summary.endswith("."):
        summary += "."
    return summary
