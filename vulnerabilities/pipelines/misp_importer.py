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
from univers.version_range import GenericVersionRange
from univers.version_range import VersionRange

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


class MISPImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect Advisories from MISP"""

    pipeline_id = "misp_importer"
    spdx_license_expression = "CC BY-SA 3.0"
    license_url = "https://www.misp-project.org/license/"
    root_url = "https://www.misp-project.org/security/"
    importer_name = "MISP Importer"

    def __init__(self):
        super().__init__()

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    # num of advisories
    def advisories_count(self) -> int:
        return len(fetch_advisory_links(self.root_url))

    # parse the response data
    def collect_advisories(self) -> Iterable[AdvisoryData]:
        advisory_links = fetch_advisory_links(self.root_url)

        for link in advisory_links:
            advisory_data = fetch_advisory_data(link)
            yield to_advisory_data(advisory_data)


def fetch_advisory_links(url):
    """Fetches the advisory links listed on the URL,returns a list"""
    r = fetch_response(url).content
    soup = BeautifulSoup(r, "html.parser")

    h2 = soup.find(id="advisories")
    # Find the <ul> element
    ul_element = h2.find_next_sibling()
    # Extract all <li> elements
    li_elements = ul_element.find_all("li")

    advisory_links = []
    # Extract and print the text content of each <li>
    for li in li_elements:
        link_text = li.find("a").text.lower()

        # Extract the rest of the text
        description = li.text.replace(link_text, "").strip()
        advisory_links.append(f"https://cve.circl.lu/vuln/fkie_{link_text}")

    return advisory_links


def fetch_advisory_data(url):
    """Fetches advisory data,returns a dict"""
    r = fetch_response(url).content
    soup = BeautifulSoup(r, "html.parser")

    # Find the <pre> element containing the JSON data
    pre_element = soup.find("pre", {"class": "json-container"})

    # Extract the text content
    json_text = pre_element.text

    # Parse the cleaned text as JSON
    json_data = json.loads(json_text)

    # data
    description = json_data["descriptions"][0]["value"]
    cve_id = json_data["id"]
    date_published = json_data["published"]
    references = json_data["references"][0]["url"]

    # metrics
    metrics = json_data["metrics"]
    metrics_keys = list(metrics.keys())
    if "cvssMetricV31" in metrics_keys:
        cve_score = {
            "version": "cvssMetricV31",
            "score": metrics["cvssMetricV31"][0]["cvssData"]["baseScore"],
        }
    else:
        cve_score = {
            "version": "cvssMetricV30",
            "score": metrics["cvssMetricV30"][0]["cvssData"]["baseScore"],
        }

    # affected version
    match = re.search(r"\b\d+\.\d+\.\d+\b", description)
    affected_version = match.group(0)

    return {
        "description": description,
        "alias": cve_id,
        "date_published": date_published,
        "references": references,
        "cve_score": cve_score,
        "affected_version": affected_version,
        "url": url,
    }


def to_advisory_data(raw_data) -> AdvisoryData:
    """Parses extracted data to Advisory Data"""
    # alias
    alias = get_item(raw_data, "alias")

    # affected packages
    affected_packages = []
    affected_version = get_item(raw_data, "affected_version")  # list of list of affected versions
    affected_packages.append(
        AffectedPackage(
            package=PackageURL(type="misp", name="MISP"),
            affected_version_range=VersionRange.from_string(f"vers:generic/={affected_version}"),
        )
    )

    # score
    if raw_data["cve_score"]["version"] == "cvssMetricV31":
        severity = VulnerabilitySeverity(
            system=CVSSV31,
            value=raw_data["cve_score"]["score"],
            scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        )
    else:
        severity = VulnerabilitySeverity(
            system=CVSSV3,
            value=raw_data["cve_score"]["score"],
            scoring_elements="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

    # Reference
    references = []
    references.append(
        Reference(
            severities=[severity],
            reference_id=alias,
            url=get_item(raw_data, "references"),
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
        aliases=alias,
        summary=description,
        affected_packages=affected_packages,
        references=references,
        url=url,
        date_published=date_published,
    )
