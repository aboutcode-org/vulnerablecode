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

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import CVSSV31
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_item

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SUDOImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect Advisories from Sudo"""

    pipeline_id = "sudo_importer"
    spdx_license_expression = "ISC"
    license_url = "https://www.sudo.ws/about/license/"
    root_url = "https://www.sudo.ws/security/advisories/"
    importer_name = "SUDO Importer"

    def __init__(self):
        super().__init__()
        self.active_pages = fetch_active_pages()
        self.advisory_links = fetch_advisory_links(self.active_pages)

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    # num of advisories
    def advisories_count(self) -> int:
        return len(self.advisory_links)

    # parse the response data
    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for link in self.advisory_links:
            advisory_data = fetch_advisory_data(link)
            yield to_advisory_data(advisory_data)


def fetch_advisory_links(active_pages):
    """Fetches advisory links from a page,returns a list"""
    advisory_links = []
    for active_page in active_pages:
        html_content = requests.get(active_page).content
        soup = BeautifulSoup(html_content, "html.parser")

        # find the a tag with the class "gdoc-post__readmore"
        readmore_links = soup.find_all("a", class_="gdoc-post__readmore")

        for readmore_link in readmore_links:
            advisory_links.append("https://www.sudo.ws" + readmore_link["href"])
    return advisory_links


def fetch_active_pages():
    """Fetches active pages which contains advisory links,returns a list"""
    page_num = 2
    active_pages = ["https://www.sudo.ws/security/advisories/"]
    while True:
        page_url = f"https://www.sudo.ws/security/advisories/page/{page_num}/"
        status = requests.get(page_url).status_code
        if status == 404:
            break
        else:
            active_pages.append(page_url)
            page_num += 1

    return active_pages


def fetch_advisory_data(advisory_link):
    """Fetches advisory data from the advisory page,returns a dict"""
    html_content = requests.get(advisory_link).content
    soup = BeautifulSoup(html_content, "html.parser")

    publication_date = soup.find("time").get("datetime", None) if soup.find("time") else None

    # extract the first p element inside <section>
    summary = (
        soup.find("section", class_="gdoc-markdown").find("p").get_text(strip=True)
        if soup.find("section", class_="gdoc-markdown")
        else None
    )

    # Extract Sudo versions affected
    versions_affected_tag = soup.find("h2", id="sudo-versions-affected")
    versions_affected = (
        versions_affected_tag.find_next("p").get_text(strip=True) if versions_affected_tag else None
    )
    versions_affected = extract_versions(versions_affected)

    cve_id_tag = soup.find("h2", id="cve-id")
    cve_id = (
        cve_id_tag.find_next("a", class_="gdoc-markdown__link").get_text(strip=True)
        if cve_id_tag
        else None
    )

    # Extract Fixed versions
    fixed_versions_tag = soup.find("h2", id="fix")
    fixed_versions = (
        fixed_versions_tag.find_next("p").get_text(strip=True) if fixed_versions_tag else None
    )
    fixed_versions = extract_versions(fixed_versions)

    return {
        "description": summary,
        "alias": cve_id,
        "date_published": publication_date,
        "affected_versions": versions_affected,
        "fixed_versions": fixed_versions,
        "url": advisory_link,
    }


def to_advisory_data(raw_data) -> AdvisoryData:
    """Parses extracted data to Advisory Data"""
    # alias
    alias = get_item(raw_data, "alias")

    # affected packages
    affected_packages = []
    affected_versions = get_item(
        raw_data, "affected_versions"
    )  # list of list of affected versions [['1.9.8', '1.9.13p1'],['1.2.9','1.2.17']]
    fixed_version = get_item(raw_data, "fixed_versions")  # [["1.2.3"]]
    for vers_range in affected_versions:  # ['1.9.8', '1.9.13p1']
        affected_packages.append(
            AffectedPackage(
                package=PackageURL(type="sudo", name="SUDO"),
                affected_version_range=VersionRange.from_string(
                    f"vers:generic/>={vers_range[0]}|<={vers_range[1]}"
                ),
                fixed_version=SemverVersion(fixed_version[0][0]),
            )
        )

    # Reference
    references = []
    references.append(
        Reference(
            reference_id=alias,
            url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={alias}",
        )
    )

    # description
    description = get_item(raw_data, "description")

    # date published
    date_published = get_item(raw_data, "date_published")
    date_published = dateparser.parse(date_published, yearfirst=True).replace(tzinfo=timezone.utc)

    # url
    url = get_item(raw_data, "url")

    return AdvisoryData(
        aliases=[alias],
        summary=description,
        affected_packages=affected_packages,
        references=references,
        url=url,
        date_published=date_published,
    )


def extract_versions(text):
    version_pattern = r"(\d+\.\d+\.\d+[a-zA-Z0-9]*)"
    versions = re.findall(version_pattern, text)
    versions = list(set(versions))

    # Group versions into pairs
    pairs = [versions[i : i + 2] for i in range(0, len(versions), 2)]

    return pairs  # returns pairs/range
