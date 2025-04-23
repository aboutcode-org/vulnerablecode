#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from datetime import timezone
from typing import Iterable

from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import OpensslVersionRange
from univers.versions import OpensslVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_item

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OpenSSLImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect Advisories from Openssl"""

    pipeline_id = "openssl_importer"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://openssl-library.org/source/license/apache-license-2.0.txt"
    root_url = "https://openssl-library.org/news/vulnerabilities/index.html"
    importer_name = "OpenSSL Importer"

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    def advisories_count(self) -> int:
        return fetch_count_advisories(self.root_url)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        raw_data = fetch_advisory_data(self.root_url)
        for data in raw_data:
            yield to_advisory_data(data)


def fetch_html_response(url):
    """
    Fetch and parse the HTML content of a given URL.

    This function sends a request to the URL, retrieves the HTML content,
    and parses it using BeautifulSoup.

    Args:
        url (str): The URL to fetch the HTML content from.

    Returns:
        A BeautifulSoup object representing the parsed HTML content.
    """
    try:
        response = fetch_response(url).content
        soup = BeautifulSoup(response, "html.parser")
        return soup
    except:
        logger.error(f"Failed to fetch URL {url}")


def fetch_count_advisories(url):
    """
    Gives the number of advisories from the given URL.
    Advisories are identified by <h3> tags.

    Args:
        url (str): The URL to fetch the advisories from.

    Returns:
        int: The number of advisories found on the page.

    Doctests:
        >>> from unittest.mock import patch
        >>> from bs4 import BeautifulSoup
        >>> from vulnerabilities.pipelines.openssl_importer import fetch_count_advisories
        >>> mock_html = '<html><body><h3>Advisory 1</h3><h3>Advisory 2</h3></body></html>'
        >>> with patch('vulnerabilities.pipelines.openssl_importer.fetch_html_response') as mock_fetch:
        ...     mock_fetch.return_value = BeautifulSoup(mock_html, "html.parser")
        ...     count = fetch_count_advisories("http://example.com")
        >>> count
        2
    """

    soup = fetch_html_response(url)
    advisories = soup.find_all("h3")
    return len(advisories)


def fetch_advisory_data(url):
    """
    Fetch advisory data from the given URL.

    Args:
        url (str): The URL to fetch the advisory data from.

    Returns:
        list: A list of dictionaries, where each dictionary contains advisory details.

    Doctests:
        >>> from unittest.mock import patch
        >>> from bs4 import BeautifulSoup
        >>> from vulnerabilities.pipelines.openssl_importer import fetch_advisory_data
        >>> mock_html = '''
        ... <html>
        ... <body>
        ... <h3 id="CVE-2024-12797">
        ...     <a href="#CVE-2024-12797">CVE-2024-12797</a>
        ... </h3>
        ... <dl>
        ...     <dt>Published at</dt>
        ...     <dd>11 February 2025</dd>
        ... </dl>
        ... </body>
        ... </html>
        ... '''
        >>> with patch('vulnerabilities.pipelines.openssl_importer.fetch_html_response') as mock_fetch:
        ...     mock_fetch.return_value = BeautifulSoup(mock_html, "html.parser")
        ...     advisories = fetch_advisory_data("http://example.com")
        >>> len(advisories)
        1
        >>> advisories[0]["CVE"]
        'CVE-2024-12797'
    """

    advisories = []
    soup = fetch_html_response(url)

    for cve_section in soup.find_all("h3"):
        data_output = {
            "date_published": "",
            "CVE": "",
            "affected_packages": [],
            "references": [],
            "summary": "",
            "severity": "",
        }

        data_output["CVE"] = cve_section.find("a").text

        dl = cve_section.find_next_sibling("dl")
        for dt, dd in zip(dl.find_all("dt"), dl.find_all("dd")):
            key = dt.text
            value = dd.text

            if key == "Severity":
                data_output["severity"] = value
            elif key == "Published at":
                data_output["date_published"] = value
            elif key == "Affected":
                affected_list = [li.text.strip() for li in dd.find_all("li")]
                data_output["affected_packages"] = affected_list
            elif key == "References":
                references = [a["href"] for a in dd.find_all("a")]
                data_output["references"] = references

        for sibling in dl.find_next_siblings():
            if sibling.name == "h2" or sibling.name == "h3":
                break
            if sibling.name == "p":
                if "Issue summary:" in sibling.text:
                    data_output["summary"] = sibling.text.strip("Issue summary:")

        advisories.append(data_output)

    return advisories


"""
{
    'date_published': '11 February 2025', 
    'CVE': 'CVE-2024-12797', 
    'affected_packages': [
        'from 3.4.0 before 3.4.1', 
        'from 3.3.0 before 3.3.3', 
        'from 3.2.0 before 3.2.4'
    ], 
    'references': ['https://www.cve.org/CVERecord?id=CVE-2024-12797', 'https://openssl-library.org/news/secadv/20250211.txt', 'https://github.com/openssl/openssl/commit/738d4f9fdeaad57660dcba50a619fafced3fd5e9', 'https://github.com/openssl/openssl/commit/87ebd203feffcf92ad5889df92f90bb0ee10a699', 'https://github.com/openssl/openssl/commit/798779d43494549b611233f92652f0da5328fbe7'], 
    'summary': 'Clients using RFC7250 Raw Public Keys (RPKs) to authenticate a\nserver may fail to notice that the server was not authenticated, because\nhandshakes don’t abort as expected when the SSL_VERIFY_PEER verification mode\nis set.', 
    'severity': 'High'
}
"""


def to_advisory_data(raw_data) -> AdvisoryData:
    """
    Convert raw advisory data into an AdvisoryData object.

    Args:
        raw_data (dict): A dictionary containing raw advisory data.

    Returns:
        AdvisoryData: An object containing structured advisory information.

    Doctests:
        >>> from unittest.mock import patch
        >>> from datetime import datetime, timezone
        >>> from vulnerabilities.pipelines.openssl_importer import to_advisory_data
        >>> raw_data = {
        ...     "CVE": "CVE-2024-12797",
        ...     "date_published": "2024-02-11",
        ...     "affected_packages": ["OpenSSL from 1.0.1 to 1.0.1j"],
        ...     "references": ["https://www.cve.org/CVERecord?id=CVE-2024-12797"],
        ...     "summary": "Example summary",
        ...     "severity": "High"
        ... }
        >>> with patch('dateparser.parse') as mock_dateparser:
        ...     mock_dateparser.return_value = datetime(2024, 2, 11, tzinfo=timezone.utc)
        ...     advisory = to_advisory_data(raw_data)
        >>> advisory.aliases
        ['CVE-2024-12797']
        >>> advisory.date_published.isoformat()
        '2024-02-11T00:00:00+00:00'
        >>> len(advisory.affected_packages)
        1
        >>> advisory.references[0].url
        'https://www.cve.org/CVERecord?id=CVE-2024-12797'
    """

    aliases = [get_item(raw_data, "CVE")]

    date_published = get_item(raw_data, "date_published")
    parsed_date_published = dateparser.parse(date_published, yearfirst=True).replace(
        tzinfo=timezone.utc
    )

    affected_packages = []
    affected_package_out = get_item(raw_data, "affected_packages")
    for affected in affected_package_out:
        if "fips" in affected:
            break
        versions = re.findall(r"(?<=from\s)([^\s]+)|(?<=before\s)([^\s]+)", affected)
        versions = [v for group in versions for v in group if v]  # ['1.0.1', '1.0.1j']
        affected_version_range = OpensslVersionRange.from_versions(versions)
        affected_packages.append(
            AffectedPackage(
                package=PackageURL(type="openssl", name="openssl"),
                affected_version_range=affected_version_range,
                fixed_version=OpensslVersion(versions[1]) if len(versions) > 1 else None,
            )
        )

    severity = VulnerabilitySeverity(
        system=SCORING_SYSTEMS["generic_textual"], value=get_item(raw_data, "severity")
    )

    references = []
    for reference in get_item(raw_data, "references"):
        references.append(Reference(severities=[severity], reference_id=aliases[0], url=reference))

    summary = get_item(raw_data, "summary")

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        date_published=parsed_date_published,
        url="https://openssl-library.org/news/vulnerabilities/index.html" + "#" + aliases[0],
    )

