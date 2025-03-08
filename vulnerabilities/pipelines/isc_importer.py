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

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import GenericVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.severity_systems import CVSSV31
from vulnerabilities.utils import get_item

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ISCImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect Advisories from ISC"""

    pipeline_id = "isc_importer"
    spdx_license_expression = "ISC"
    license_url = "https://opensource.org/license/isc-license-txt"
    root_url = "https://kb.isc.org/docs/aa-00913"
    importer_name = "ISC Importer"

    def __init__(self):
        super().__init__()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    # num of advisories
    def advisories_count(self) -> int:
        return len(fetch_advisory_data(self.root_url, self.headers))

    # parse the response data
    def collect_advisories(self) -> Iterable[AdvisoryData]:
        advisory_links = fetch_advisory_links(self.root_url, self.headers)

        for link in advisory_links:
            advisory_data = fetch_advisory_data(link, self.headers)
            yield to_advisory_data(advisory_data)


def fetch_advisory_links(url, headers):
    """Fetches the advisory links listed on the URL,returns a list"""
    reponse = requests.get(url, headers=headers)
    r_content = reponse.content

    soup = BeautifulSoup(r_content, "html.parser")

    hyperlink_wrapper = soup.find("h4")
    table = hyperlink_wrapper.find_next_sibling("table")
    advisory_links = []
    # Extract the link from the 3rd <td> in each row
    for row in table.find_all("tr"):  # Iterate through all rows
        cells = row.find_all("td")  # Find all <td> elements in the row
        if len(cells) >= 3:  # Ensure there are at least 3 <td> elements
            third_td = cells[2]  # Get the 3rd <td> element
            link = third_td.find("a")  # Find the <a> tag inside the 3rd <td>
            if link["href"].startswith("https") == False:
                advisory_links.append("https://kb.isc.org" + link["href"])
            else:
                advisory_links.append(link["href"])

    return advisory_links


def fetch_advisory_data(advisory_link, headers):
    """Fetches advisory data,returns a dict"""
    reponse = requests.get(advisory_link, headers=headers)
    r_content = reponse.content

    soup = BeautifulSoup(r_content, "html.parser")

    soup = soup.find(id="articleContent")

    # Extract CVE Link
    cve_link = soup.find("a")["href"]
    cve = soup.find("a").text

    # Extract Posting Date
    posting_date_tag = soup.find("strong", text=re.compile(r"Posting date:"))
    posting_date = posting_date_tag.parent.text.replace("Posting date:", "").strip()

    # Extract Versions Affected
    versions_affected = []
    for li in soup.find_all("li", text=re.compile(r"\d+\.\d+\.\d+")):
        version_range = li.text.strip()
        if "->" in version_range:
            start, end = version_range.split("->")
            versions_affected.append([start.strip(), end.strip()])

    # Extract Severity
    severity_tag = soup.find("strong", text=re.compile(r"Severity:"))
    severity = severity_tag.parent.text.replace("Severity:", "").strip()

    # Extract Description
    description_tag = soup.find("strong", text=re.compile(r"Description:"))
    description = description_tag.find_next("p").text.strip()

    # Extract CVSS Score
    cvss_score_tag = soup.find("strong", text=re.compile(r"CVSS Score:"))
    cvss_score = cvss_score_tag.parent.text.replace("CVSS Score:", "").strip()

    # Extract Fixed Versions (from Solution area)
    fixed_versions = []
    solution_area = soup.find("strong", text=re.compile(r"Solution:"))
    for li in solution_area.find_next("ul").find_all("li"):
        fixed_versions.append(li.text.strip())

    return {
        "cve_link": cve_link,
        "cve": cve,
        "date_published": posting_date,
        "severity": severity,
        "Affected": versions_affected,
        "Fixed": fixed_versions,
        "Score": cvss_score,
        "Description": description,
    }


def to_advisory_data(raw_data) -> AdvisoryData:
    """Parses extracted data to Advisory Data"""
    # alias
    alias = get_item(raw_data, "cve")

    # fixed versions
    fixed_versions = get_item(raw_data, "Fixed")

    # affected packages
    affected_packages = []
    affected_versions_list = get_item(raw_data, "Affected")  # list of list of affected versions
    for affected_versions, fixed_version in zip(affected_versions_list, fixed_versions):
        affected_packages.append(
            AffectedPackage(
                package=PackageURL(type="isc", name="BIND"),
                affected_version_range=GenericVersionRange(affected_versions),
                fixed_version=fixed_version,
            )
        )

    # score
    score = get_item(raw_data, "Score")
    severity = VulnerabilitySeverity(
        system=CVSSV31, value=score, scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    )
    # Reference
    references = []
    references.append(
        Reference(
            severities=[severity],
            reference_id=alias,
            url=get_item(raw_data, "cve_link"),
        )
    )

    # description
    description = get_item(raw_data, "Description")

    # date published
    date_published = get_item(raw_data, "date_published")
    date_published = dateparser.parse(date_published, yearfirst=True).replace(tzinfo=timezone.utc)

    return AdvisoryData(
        aliases=alias,
        summary=description,
        affected_packages=affected_packages,
        references=references,
        url=f"https://kb.isc.org/v1/docs/{get_item(raw_data,'cve').lower()}",
        date_published=date_published,
    )
