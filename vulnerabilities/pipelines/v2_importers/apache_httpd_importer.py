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
import urllib.parse
from typing import Iterable

import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import ApacheVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import APACHE_HTTPD
from vulnerabilities.utils import create_weaknesses_list
from vulnerabilities.utils import cwe_regex
from vulnerabilities.utils import get_item

logger = logging.getLogger(__name__)


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


class ApacheHTTPDImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Apache HTTPD Importer Pipeline

    This pipeline imports security advisories from the Apache HTTPD project.
    """

    pipeline_id = "apache_httpd_importer_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"
    base_url = "https://httpd.apache.org/security/json/"

    links = []

    ignorable_versions = frozenset(
        [
            "AGB_BEFORE_AAA_CHANGES",
            "APACHE_1_2b1",
            "APACHE_1_2b10",
            "APACHE_1_2b11",
            "APACHE_1_2b2",
            "APACHE_1_2b3",
            "APACHE_1_2b4",
            "APACHE_1_2b5",
            "APACHE_1_2b6",
            "APACHE_1_2b7",
            "APACHE_1_2b8",
            "APACHE_1_2b9",
            "APACHE_1_3_PRE_NT",
            "APACHE_1_3a1",
            "APACHE_1_3b1",
            "APACHE_1_3b2",
            "APACHE_1_3b3",
            "APACHE_1_3b5",
            "APACHE_1_3b6",
            "APACHE_1_3b7",
            "APACHE_2_0_2001_02_09",
            "APACHE_2_0_52_WROWE_RC1",
            "APACHE_2_0_ALPHA",
            "APACHE_2_0_ALPHA_2",
            "APACHE_2_0_ALPHA_3",
            "APACHE_2_0_ALPHA_4",
            "APACHE_2_0_ALPHA_5",
            "APACHE_2_0_ALPHA_6",
            "APACHE_2_0_ALPHA_7",
            "APACHE_2_0_ALPHA_8",
            "APACHE_2_0_ALPHA_9",
            "APACHE_2_0_BETA_CANDIDATE_1",
            "APACHE_BIG_SYMBOL_RENAME_POST",
            "APACHE_BIG_SYMBOL_RENAME_PRE",
            "CHANGES",
            "HTTPD_LDAP_1_0_0",
            "INITIAL",
            "MOD_SSL_2_8_3",
            "PCRE_3_9",
            "POST_APR_SPLIT",
            "PRE_APR_CHANGES",
            "STRIKER_2_0_51_RC1",
            "STRIKER_2_0_51_RC2",
            "STRIKER_2_1_0_RC1",
            "WROWE_2_0_43_PRE1",
            "apache-1_3-merge-1-post",
            "apache-1_3-merge-1-pre",
            "apache-1_3-merge-2-post",
            "apache-1_3-merge-2-pre",
            "apache-apr-merge-3",
            "apache-doc-split-01",
            "dg_last_1_2_doc_merge",
            "djg-apache-nspr-07",
            "djg_nspr_split",
            "moving_to_httpd_module",
            "mpm-3",
            "mpm-merge-1",
            "mpm-merge-2",
            "post_ajp_proxy",
            "pre_ajp_proxy",
        ]
    )

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        if not self.links:
            self.links = fetch_links(self.base_url)
        for link in self.links:
            data = requests.get(link).json()
            yield self.to_advisory(data)

    def advisories_count(self) -> int:
        """Count the number of advisories available in the JSON files."""
        if not self.links:
            self.links = fetch_links(self.base_url)
        return len(self.links)

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
        reference = ReferenceV2(
            reference_id=alias,
            url=urllib.parse.urljoin(self.base_url, f"{alias}.json"),
        )

        versions_data = []
        for vendor in get_item(data, "affects", "vendor", "vendor_data") or []:
            for products in get_item(vendor, "product", "product_data") or []:
                for version_data in get_item(products, "version", "version_data") or []:
                    versions_data.append(version_data)

        fixed_versions = []
        date_published = None
        for timeline_object in data.get("timeline") or []:
            timeline_value = timeline_object.get("value")
            if timeline_value == "public":
                date_published = timeline_object.get("time")
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
                AffectedPackageV2(
                    package=PackageURL(
                        type="apache",
                        name="httpd",
                    ),
                    affected_version_range=affected_version_range,
                )
            )

        weaknesses = get_weaknesses(data)

        return AdvisoryData(
            advisory_id=alias,
            aliases=[],
            summary=description or "",
            affected_packages=affected_packages,
            references_v2=[reference],
            weaknesses=weaknesses,
            url=reference.url,
            severities=severities,
            original_advisory_text=json.dumps(data, indent=2, ensure_ascii=False),
            date_published=date_parser.parse(date_published) if date_published else None,
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
