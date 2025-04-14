#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import logging
import re
from datetime import timezone
from typing import Iterable

import dateparser
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion

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


class ApacheCamelImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect Advisories from Apache Camel"""

    pipeline_id = "apache_camel_importer"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"
    root_url = "https://camel.apache.org/security/"
    importer_name = "Apache Camel Importter"

    def __init__(self):
        super().__init__()

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    def advisories_count(self) -> int:
        return fetch_count_advisories(self.root_url)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        adv_data = fetch_advisory_data(self.root_url)
        for data in adv_data:
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
    Advisories are identified by <tr> tags.

    Args:
        url (str): The URL to fetch the advisories from.

    Returns:
        int: The number of advisories found on the page.

    Doctests:
        >>> from unittest.mock import patch
        >>> from bs4 import BeautifulSoup
        >>> from vulnerabilities.pipelines.apache_camel_importer import fetch_count_advisories
        >>> mock_html = '''
        ... <html>
        ... <body>
        ... <table>
        ... <tbody>
        ... <tr><td>Advisory 1</td></tr>
        ... <tr><td>Advisory 2</td></tr>
        ... <tr><td>Advisory 3</td></tr>
        ... </tbody>
        ... </table>
        ... </body>
        ... </html>
        ... '''
        >>> with patch('vulnerabilities.pipelines.apache_camel_importer.fetch_html_response') as mock_fetch:
        ...     mock_fetch.return_value = BeautifulSoup(mock_html, "html.parser")
        ...     count = fetch_count_advisories("http://example.com")
        >>> count
        3
    """

    soup = fetch_html_response(url)
    table = soup.find("tbody")
    advisory_len = len(table.find_all("tr"))

    return advisory_len


def fetch_advisory_data(url):
    """
    Fetch advisory data from the given URL.

    Args:
        url (str): The URL to fetch the advisory data from.

    Returns:
        list: A list of dictionaries, where each dictionary contains advisory details.

    Doctests:
        >>> from unittest.mock import patch
        >>> mock_html = '''
        ... <html>
        ... <body>
        ... <table>
        ... <tbody>
        ... <tr>
        ...     <td>CVE-2025-30177</td>
        ...     <td>Apache Camel 4.10.0 before 4.10.3</td>
        ...     <td>4.10.3</td>
        ...     <td>MEDIUM</td>
        ...     <td>Camel-Undertow Message Header Injection</td>
        ... </tr>
        ... <tr>
        ...     <td>CVE-2025-30178</td>
        ...     <td>Apache Camel 4.8.0 before 4.8.6</td>
        ...     <td>4.8.6</td>
        ...     <td>HIGH</td>
        ...     <td>Another vulnerability description</td>
        ... </tr>
        ... </tbody>
        ... </table>
        ... </body>
        ... </html>
        ... '''
        >>> with patch('vulnerabilities.pipelines.apache_camel_importer.fetch_html_response') as mock_fetch:
        ...     mock_fetch.return_value = BeautifulSoup(mock_html, "html.parser")
        ...     advisories = fetch_advisory_data("http://example.com")
        >>> len(advisories)
        2
        >>> advisories[0]['Reference']
        'CVE-2025-30177'
        >>> advisories[0]['Affected']
        'Apache Camel 4.10.0 before 4.10.3'
    """

    soup = fetch_html_response(url)
    table = soup.find("tbody")

    advisories = []

    for row in table.find_all("tr"):
        columns = row.find_all("td")
        if len(columns) == 5:
            reference = columns[0].text.strip()
            affected = columns[1].text.strip()
            fixed = columns[2].text.strip()
            score = columns[3].text.strip()
            description = columns[4].text.strip()

            advisories.append(
                {
                    "Reference": reference,
                    "Affected": affected,
                    "Fixed": fixed,
                    "Score": score,
                    "Description": description,
                }
            )

    return advisories


"""
{
    'Reference': 'CVE-2025-30177', 
    'Affected': 'Apache Camel 4.10.0 before 4.10.3. Apache Camel 4.8.0 before 4.8.6.', 
    'Fixed': '4.8.6 and 4.10.3', 
    'Score': 'MEDIUM', 
    'Description': 'Camel-Undertow Message Header Injection via Improper Filtering'
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
        >>> from vulnerabilities.pipelines.apache_camel_importer import fetch_date_published
        >>> from vulnerabilities.pipelines.apache_camel_importer import to_advisory_data
        >>> from vulnerabilities.importer import AdvisoryData
        >>> raw_data = {
        ...     'Reference': 'CVE-2025-30177',
        ...     'Affected': 'Apache Camel 4.10.0 before 4.10.3. Apache Camel 4.8.0 before 4.8.6.',
        ...     'Fixed': '4.8.6 and 4.10.3',
        ...     'Score': 'MEDIUM',
        ...     'Description': 'Camel-Undertow Message Header Injection via Improper Filtering'
        ... }
        >>> with patch('vulnerabilities.pipelines.apache_camel_importer.fetch_date_published') as mock_fetch_date_published:
        ...     mock_fetch_date_published.return_value = "2025-04-01T11:56:30.484000+00:00"
        ...     advisory = to_advisory_data(raw_data)
        >>> advisory.aliases
        ['CVE-2025-30177']
        >>> advisory.summary
        'Camel-Undertow Message Header Injection via Improper Filtering'
        >>> len(advisory.affected_packages)
        1
        >>> advisory.affected_packages[0].package.name
        'camel'
    """

    alias = get_item(raw_data, "Reference")

    version_pattern = re.compile(r"\b\d+\.\d+\.\d+\b")
    fixed_version_out = get_item(raw_data, "Fixed")
    fixed_versions = []
    for fixed_version in version_pattern.findall(fixed_version_out):
        fixed_versions.append(MavenVersion(fixed_version))

    affected_packages = []
    affected_package_string = get_item(raw_data, "Affected")
    affected_package = parse_apache_camel_versions(affected_package_string)
    affected_packages.append(
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="org.apache.camel",
                name="camel",
            ),
            affected_version_range=affected_package,
        )
    )

    score = get_item(raw_data, "Score")
    severity = VulnerabilitySeverity(system=SCORING_SYSTEMS["generic_textual"], value=score)

    references = []
    references.append(
        Reference(
            severities=[severity],
            reference_id=alias,
            url=f"https://camel.apache.org/security/{alias}.html",
        )
    )

    description = get_item(raw_data, "Description")

    date_published = fetch_date_published(alias)
    parsed_date_published = dateparser.parse(date_published).replace(tzinfo=timezone.utc)

    return AdvisoryData(
        aliases=[alias],
        summary=description,
        affected_packages=affected_packages,
        references=references,
        url=f"https://camel.apache.org/security/{alias}.html",
        date_published=parsed_date_published,
    )


def fetch_date_published(cve):
    """Fetches Date of a CVE"""

    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    response = fetch_response(url).content
    response = json.loads(response)
    return response["cveMetadata"]["datePublished"]


def parse_apache_camel_versions(version_string):
    """Parse version strings from Apache Camel advisories into version constraints"""

    version_ranges = []

    # Handle "from X before Y"
    for match in re.finditer(r"from ([\d\w.-]+) before ([\d\w.-]+)", version_string):
        start_version, end_version = match.groups()
        version_ranges.extend(
            [
                VersionConstraint(comparator=">=", version=MavenVersion(start_version)),
                VersionConstraint(comparator="<", version=MavenVersion(end_version)),
            ]
        )

    # Handle "from X up to Y"
    for match in re.finditer(r"from ([\d\w.-]+) up to ([\d\w.-]+)", version_string):
        start_version, end_version = match.groups()
        version_ranges.extend(
            [
                VersionConstraint(comparator=">=", version=MavenVersion(start_version)),
                VersionConstraint(comparator="<=", version=MavenVersion(end_version)),
            ]
        )

    # Handle isolated versions like `3.19.0`
    for match in re.finditer(r"(\d+\.\d+\.\d+)", version_string):
        version = match.group(1)
        version_ranges.append(VersionConstraint(comparator="=", version=MavenVersion(version)))

    # Handle X.x style like 2.22.x
    for match in re.finditer(r"(\d+\.\d+)\.x", version_string):
        version_prefix = match.group(1)
        start_version = f"{version_prefix}.0"
        end_version = f"{version_prefix}.99999"  # To cover all patch versions
        version_ranges.extend(
            [
                VersionConstraint(comparator=">=", version=MavenVersion(start_version)),
                VersionConstraint(comparator="<=", version=MavenVersion(end_version)),
            ]
        )

    return MavenVersionRange(constraints=version_ranges)
