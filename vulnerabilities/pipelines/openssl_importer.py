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
    spdx_license_expression = "OpenSSL-standalone"
    license_url = "https://spdx.org/licenses/OpenSSL-standalone.html"
    root_url = "https://openssl-library.org/news/vulnerabilities/index.html"
    importer_name = "OpenSSL Importer"

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    # num of advisories
    def advisories_count(self) -> int:
        return fetch_count_advisories(self.root_url)

    # parse the response data
    def collect_advisories(self) -> Iterable[AdvisoryData]:
        raw_data = fetch_advisory_data(self.root_url)
        for data in raw_data:
            yield to_advisory_data(data)


# fetch the html content
def fetch_html_response(url):
    try:
        response = fetch_response(url).content
        soup = BeautifulSoup(response, "html.parser")
        return soup
    except:
        logger.error(f"Failed to fetch URL {url}")


def fetch_count_advisories(url):
    soup = fetch_html_response(url)
    advisories = soup.find_all("h3")
    return len(advisories)


# fetch the content from the html data
def fetch_advisory_data(url):
    advisories = []
    soup = fetch_html_response(url)
    # all the CVEs are h3 with id="CVE-.."
    for cve_section in soup.find_all("h3"):
        data_output = {
            "date_published": "",
            "CVE": "",
            "affected_packages": [],
            "references": [],
            "summary": "",
            "severity": "",
        }

        # CVE is in a link
        data_output["CVE"] = cve_section.find("a").text

        # the <dl> tag in this section
        dl = cve_section.find_next_sibling("dl")
        for dt, dd in zip(
            dl.find_all("dt"), dl.find_all("dd")
        ):  # combines both the lists,for better iteration
            key = dt.text
            value = dd.text

            # Severity
            if key == "Severity":
                data_output["severity"] = value
            # Published Date
            elif key == "Published at":
                data_output["date_published"] = value
            # Affected Packages
            elif key == "Affected":
                affected_list = [li.text.strip() for li in dd.find_all("li")]
                data_output["affected_packages"] = affected_list
            # references
            elif key == "References":
                references = [a["href"] for a in dd.find_all("a")]
                data_output["references"] = references

        # for summary
        for sibling in dl.find_next_siblings():
            if sibling.name == "h2" or sibling.name == "h3":
                break
            if sibling.name == "p":
                if "Issue summary:" in sibling.text:
                    data_output["summary"] = sibling.text.strip("Issue summary:")

        # append all the output  data to the list
        advisories.append(data_output)

    # return the list with all the advisory data
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


# parse the advisory data
def to_advisory_data(raw_data) -> AdvisoryData:
    # alias
    aliases = [get_item(raw_data, "CVE")]

    # published data
    date_published = get_item(raw_data, "date_published")
    parsed_date_published = dateparser.parse(date_published, yearfirst=True).replace(
        tzinfo=timezone.utc
    )

    # affected packages
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
            )
        )

    # Severity
    severity = VulnerabilitySeverity(
        system=SCORING_SYSTEMS["generic_textual"], value=get_item(raw_data, "severity")
    )

    # Reference
    references = []
    for reference in get_item(raw_data, "references"):
        references.append(Reference(severities=[severity], reference_id=aliases[0], url=reference))

    # summary
    summary = get_item(raw_data, "summary")

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        date_published=parsed_date_published,
        url="https://openssl-library.org/news/vulnerabilities/index.html" + "#" + aliases[0],
    )
