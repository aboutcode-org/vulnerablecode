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



def fetch_count_advisories(url):
    """Return the count of advisories"""

    response = fetch_response(url).content
    soup = BeautifulSoup(response, "html.parser")
    table = soup.find("tbody")
    advisory_len = len(table.find_all("tr"))

    return advisory_len


def fetch_advisory_data(url):
    """Fetch advisory data from the table and return a list containing all the advisories"""
    response = fetch_response(url).content
    soup = BeautifulSoup(response, "html.parser")

    table = soup.find("tbody")

    advisories = []

    for row in table.find_all("tr"):
        columns = row.find_all("td")
        if len(columns) == 5:  #Ensure it's a row with data (not headers or empty rows)
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


def to_advisory_data(raw_data) -> AdvisoryData:
    """Parses extracted data to Advisory Data"""
 
    alias = get_item(raw_data, "Reference")

    version_pattern = re.compile(r"\b\d+\.\d+\.\d+\b")
    fixed_version_out = get_item(raw_data, "Fixed")
    fixed_versions = []
    for fixed_version in version_pattern.findall(fixed_version_out):
        fixed_versions.append(MavenVersion(fixed_version))
    print(fixed_versions)

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
            fixed_version=fixed_versions
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


imp = ApacheCamelImporterPipeline()
adv = imp.collect_advisories()
print(next(adv))