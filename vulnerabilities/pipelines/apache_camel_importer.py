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
from datetime import datetime
from datetime import timezone
from typing import Iterable
from typing import Tuple

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import MavenVersionRange
from univers.version_range import VersionRange
from univers.versions import GenericVersion
from univers.versions import MavenVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.severity_systems import GENERIC
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
        self.raw_data = None

    @classmethod
    def steps(cls):
        return (
            cls.fetch_html_response,
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    # fetch the html content and saves in raw_data
    def fetch_html_response(self):
        try:
            response = fetch_response(self.root_url).content
            self.raw_data = BeautifulSoup(response, "html.parser")
        except:
            logger.error(f"Failed to fetch URL {self.root_url}")

    # num of advisories
    def advisories_count(self) -> int:
        return fetch_count_advisories(self.raw_data)

    # parse the response data
    def collect_advisories(self) -> Iterable[AdvisoryData]:
        adv_data = fetch_advisory_data(self.raw_data)
        for data in adv_data:
            yield to_advisory_data(data)


# fetch the html content
def fetch_html_response(url):
    try:
        response = fetch_response(url).content
        soup = BeautifulSoup(response, "html.parser")
        return soup
    except:
        logger.error(f"Failed to fetch URL {url}")


def fetch_count_advisories(soup):
    # soup = fetch_html_response(url)
    table = soup.find("tbody")
    advisory_len = len(table.find_all("tr"))
    return advisory_len


# fetch the content from the html data
def fetch_advisory_data(soup):
    advisories = []
    # soup = fetch_html_response(url)

    # Find the table containing the security advisories,ignoring the thead
    table = soup.find("tbody")

    # Initialize a list to store the extracted data
    advisories = []

    # Iterate through each row in the table
    for row in table.find_all("tr"):
        columns = row.find_all("td")
        if len(columns) == 5:  # Ensure it's a row with data (not headers or empty rows)
            reference = columns[0].text.strip()
            affected = columns[1].text.strip()
            fixed = columns[2].text.strip()
            score = columns[3].text.strip()
            description = columns[4].text.strip()

            # Append the extracted data to the list
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


def to_advisory_data(raw_data) -> AdvisoryData:
    """Parses extracted data to Advisory Data"""
    # alias
    alias = get_item(raw_data, "Reference")

    # affected packages
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

    # fixed versions
    version_pattern = re.compile(r"\b\d+\.\d+\.\d+\b")
    fixed_version_out = get_item(raw_data, "Fixed")
    fixed_versions = version_pattern.findall(fixed_version_out)

    # score
    score = get_item(raw_data, "Score")  # words not numbers
    severity = VulnerabilitySeverity(system=SCORING_SYSTEMS["generic_textual"], value=score)
    # Reference
    references = []
    references.append(
        Reference(
            severities=[severity],
            reference_id=alias,
            url=f"https://camel.apache.org/security/{alias}.html",
        )
    )

    # description
    description = get_item(raw_data, "Description")

    return AdvisoryData(
        aliases=alias,
        summary=description,
        affected_packages=affected_packages,
        references=references,
        url=f"https://camel.apache.org/security/{alias}.html",
    )


def parse_apache_camel_versions(version_string):
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

