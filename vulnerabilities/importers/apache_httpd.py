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
import urllib

import requests
from bs4 import BeautifulSoup
from cwe2.database import Database
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import ApacheVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import APACHE_HTTPD
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item

logger = logging.getLogger(__name__)


class ApacheHTTPDImporter(Importer):

    base_url = "https://httpd.apache.org/security/json/"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"
    importer_name = "Apache HTTPD Importer"

    def advisory_data(self):
        links = fetch_links(self.base_url)
        for link in links:
            data = requests.get(link).json()
            yield self.to_advisory(data)

    def to_advisory(self, data):
        alias = get_item(data, "CVE_data_meta", "ID")
        if not alias:
            alias = get_item(data, "cveMetadata", "cveId")
        descriptions = get_item(data, "description", "description_data") or []
        description = None
        for desc in descriptions:
            if desc.get("lang") == "eng":
                description = desc.get("value")
                break

        severities = []
        impacts = data.get("impact") or []
        for impact in impacts:
            value = impact.get("other")
            if value:
                severities.append(
                    VulnerabilitySeverity(
                        system=APACHE_HTTPD,
                        value=value,
                        scoring_elements="",
                    )
                )
                break
        reference = Reference(
            reference_id=alias,
            url=urllib.parse.urljoin(self.base_url, f"{alias}.json"),
            severities=severities,
        )

        versions_data = []
        for vendor in get_item(data, "affects", "vendor", "vendor_data") or []:
            for products in get_item(vendor, "product", "product_data") or []:
                for version_data in get_item(products, "version", "version_data") or []:
                    versions_data.append(version_data)

        fixed_versions = []
        for timeline_object in data.get("timeline") or []:
            timeline_value = timeline_object.get("value")
            if "release" in timeline_value:
                split_timeline_value = timeline_value.split(" ")
                if "never" in timeline_value:
                    continue
                if "release" in split_timeline_value[-1]:
                    fixed_versions.append(split_timeline_value[0])
                if "release" in split_timeline_value[0]:
                    fixed_versions.append(split_timeline_value[-1])

        affected_packages = []
        affected_version_range = self.to_version_ranges(versions_data, fixed_versions)
        if affected_version_range:
            affected_packages.append(
                AffectedPackage(
                    package=PackageURL(
                        type="apache",
                        name="httpd",
                    ),
                    affected_version_range=affected_version_range,
                )
            )

        weaknesses = get_weaknesses(data)

        return AdvisoryData(
            aliases=[alias],
            summary=description or "",
            affected_packages=affected_packages,
            references=[reference],
            weaknesses=weaknesses,
            url=reference.url,
        )

    def to_version_ranges(self, versions_data, fixed_versions):
        constraints = []
        for version_data in versions_data:
            version_value = version_data["version_value"]
            range_expression = version_data["version_affected"]
            if range_expression not in {"<=", ">=", "?=", "!<", "="}:
                raise ValueError(f"unknown comparator found! {range_expression}")
            comparator_by_range_expression = {
                ">=": ">=",
                "!<": ">=",
                "<=": "<=",
                "=": "=",
            }
            comparator = comparator_by_range_expression.get(range_expression)
            if comparator:
                constraints.append(
                    VersionConstraint(comparator=comparator, version=SemverVersion(version_value))
                )

        for fixed_version in fixed_versions:
            # The VersionConstraint method `invert()` inverts the fixed_version's comparator,
            # enabling inclusion of multiple fixed versions with the `affected_version_range` values.
            constraints.append(
                VersionConstraint(
                    comparator="=",
                    version=SemverVersion(fixed_version),
                ).invert()
            )

        return ApacheVersionRange(constraints=constraints)


def fetch_links(url):
    links = []
    data = requests.get(url).content
    soup = BeautifulSoup(data, features="lxml")
    for tag in soup.find_all("a"):
        link = tag.get("href")
        if not link.endswith("json"):
            continue
        links.append(urllib.parse.urljoin(url, link))
    return links


def get_weaknesses(cve_data):
    """
    Extract CWE IDs from CVE data.

    Args:
        cve_data (dict): The CVE data in a dictionary format.

    Returns:
        List[int]: A list of unique CWE IDs.

    >>> mock_cve_data = {
    ... "containers": {
    ... "cna": {
    ... "providerMetadata": {
    ... "orgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09"
    ...  },
    ...  "title": "mod_macro buffer over-read",
    ...  "problemTypes": [
    ...    {
    ...      "descriptions": [
    ...        {
    ...          "description": "CWE-125 Out-of-bounds Read",
    ...          "lang": "en",
    ...          "cweId": "CWE-125",
    ...          "type": "CWE"
    ...        }
    ...      ]
    ...    }
    ...  ]
    ... }
    ... }
    ... }
    >>> get_weaknesses(mock_cve_data)
    [125]
    """
    problem_types = cve_data.get("containers", {}).get("cna", {}).get("problemTypes", [])
    descriptions = problem_types[0].get("descriptions", []) if len(problem_types) > 0 else []
    cwe_string = descriptions[0].get("cweId", "") if len(descriptions) > 0 else ""
    cwe_pattern = r"CWE-\d+"
    description = descriptions[0].get("description", "") if len(descriptions) > 0 else ""
    matches = re.findall(cwe_pattern, description)
    db = Database()
    weaknesses = []
    cwe_string_from_description = ""
    if matches:
        cwe_string_from_description = matches[0]
    if cwe_string or cwe_string_from_description:
        if cwe_string:
            cwe_id = get_cwe_id(cwe_string)
            try:
                db.get(cwe_id)
                weaknesses.append(cwe_id)
            except Exception:
                logger.error("Invalid CWE id")
        elif cwe_string_from_description:
            cwe_id = get_cwe_id(cwe_string_from_description)
            try:
                db.get(cwe_id)
                weaknesses.append(cwe_id)
            except Exception:
                logger.error("Invalid CWE id")

    seen = set()
    unique_cwe = [x for x in weaknesses if not (x in seen or seen.add(x))]
    return unique_cwe
