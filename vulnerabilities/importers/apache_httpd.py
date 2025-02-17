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
import urllib

import requests
from bs4 import BeautifulSoup
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
from vulnerabilities.utils import create_weaknesses_list
from vulnerabilities.utils import cwe_regex
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

    Examples:
        >>> mock_cve_data1 = {
        ...     "containers": {
        ...         "cna": {
        ...             "providerMetadata": {
        ...                 "orgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09"
        ...             },
        ...             "title": "mod_macro buffer over-read",
        ...             "problemTypes": [
        ...                 {
        ...                     "descriptions": [
        ...                         {
        ...                             "description": "CWE-125 Out-of-bounds Read",
        ...                             "lang": "en",
        ...                             "cweId": "CWE-125",
        ...                             "type": "CWE"
        ...                         }
        ...                     ]
        ...                 }
        ...             ]
        ...         }
        ...     }
        ... }
        >>> mock_cve_data2 = {
        ...     "data_type": "CVE",
        ...     "data_format": "MITRE",
        ...     "data_version": "4.0",
        ...     "generator": {
        ...         "engine": "Vulnogram 0.0.9"
        ...     },
        ...     "CVE_data_meta": {
        ...         "ID": "CVE-2022-28614",
        ...         "ASSIGNER": "security@apache.org",
        ...         "TITLE": "read beyond bounds via ap_rwrite() ",
        ...         "STATE": "PUBLIC"
        ...     },
        ...     "problemtype": {
        ...         "problemtype_data": [
        ...             {
        ...                 "description": [
        ...                     {
        ...                         "lang": "eng",
        ...                         "value": "CWE-190 Integer Overflow or Wraparound"
        ...                     }
        ...                 ]
        ...             },
        ...             {
        ...                 "description": [
        ...                     {
        ...                         "lang": "eng",
        ...                         "value": "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor"
        ...                     }
        ...                 ]
        ...             }
        ...         ]
        ...     }
        ... }

        >>> get_weaknesses(mock_cve_data1)
        [125]

        >>> get_weaknesses(mock_cve_data2)
        [190, 200]
    """
    alias = get_item(cve_data, "CVE_data_meta", "ID")
    cwe_strings = []
    if alias:
        problemtype_data = get_item(cve_data, "problemtype", "problemtype_data") or []
        for problem in problemtype_data:
            for desc in problem.get("description", []):
                value = desc.get("value", "")
                cwe_id_string_list = re.findall(cwe_regex, value)
                cwe_strings.extend(cwe_id_string_list)
    else:
        problemTypes = cve_data.get("containers", {}).get("cna", {}).get("problemTypes", [])
        descriptions = problemTypes[0].get("descriptions", []) if len(problemTypes) > 0 else []
        for description in descriptions:
            cwe_id_string = description.get("cweId", "")
            cwe_strings.append(cwe_id_string)

    weaknesses = create_weaknesses_list(cwe_strings)
    return weaknesses
