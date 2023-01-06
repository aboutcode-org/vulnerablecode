#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import asyncio
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


class ApacheHTTPDImporter(Importer):

    base_url = "https://httpd.apache.org/security/json/"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"

    def advisory_data(self):
        links = fetch_links(self.base_url)
        for link in links:
            data = requests.get(link).json()
            yield self.to_advisory(data)

    def to_advisory(self, data):
        alias = data["CVE_data_meta"]["ID"]
        descriptions = data["description"]["description_data"]
        description = None
        for desc in descriptions:
            if desc["lang"] == "eng":
                description = desc.get("value")
                break

        severities = []
        impacts = data.get("impact", [])
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
        for vendor in data["affects"]["vendor"]["vendor_data"]:
            for products in vendor["product"]["product_data"]:
                for version_data in products["version"]["version_data"]:
                    versions_data.append(version_data)

        fixed_versions = []
        for timeline_object in data.get("timeline") or []:
            timeline_value = timeline_object["value"]
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

        return AdvisoryData(
            aliases=[alias],
            summary=description,
            affected_packages=affected_packages,
            references=[reference],
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


ignore_tags = {
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
}
