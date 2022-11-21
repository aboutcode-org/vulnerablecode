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
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.severity_systems import APACHE_HTTPD

# from vulnerabilities.utils import nearest_patched_package


class ApacheHTTPDImporter(Importer):

    base_url = "https://httpd.apache.org/security/json/"

    # For now, don't use the GH API
    # def set_api(self):
    #     self.version_api = GitHubTagsAPI()
    #     asyncio.run(self.version_api.load_api(["apache/httpd"]))
    #     self.version_api.cache["apache/httpd"] = set(
    #         filter(
    #             lambda version: version.value not in ignore_tags,
    #             self.version_api.cache["apache/httpd"],
    #         )
    #     )

    def updated_advisories(self):
        links = fetch_links(self.base_url)
        # For now, don't use the GH API
        # self.set_api()
        advisories = []
        for link in links:
            data = requests.get(link).json()
            advisories.append(self.to_advisory(data))
        return self.batch_advisories(advisories)

    def to_advisory(self, data):
        # cve = data["CVE_data_meta"]["ID"]
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
                    )
                )
                break
        reference = Reference(
            # reference_id=cve,
            reference_id=alias,
            # url=urllib.parse.urljoin(self.base_url, f"{cve}.json"),
            url=urllib.parse.urljoin(self.base_url, f"{alias}.json"),
            severities=severities,
        )

        # 2022-11-17 Thursday 19:02:16.  This redraft of mine looks wrong and unnecessary -- current approach looks like what we want, since sampling suggests there are no real references in the JSON data and that there's always one value in ["impact"]["other"]
        # reference_list = []
        # # reference_data = data["references"]
        # # if data["references"]["reference_data"]:
        # if "reference_data" in data.get("references", {}):
        #     reference = Reference(
        #         reference_id=data["references"]["reference_data"][0]["refsource"],
        #         url=data["references"]["reference_data"][0]["refsource"],
        #         severities=severities,
        #     )
        # else:
        #     reference = Reference(
        #         reference_id="",
        #         url="",
        #         severities=severities,
        #     )

        versions_data = []
        for vendor in data["affects"]["vendor"]["vendor_data"]:
            for products in vendor["product"]["product_data"]:
                for version_data in products["version"]["version_data"]:
                    versions_data.append(version_data)

        print("\n\n==> versions_data = {}\n".format(versions_data))
        for version in versions_data:
            print("\n\tversion = {}\n".format(version))
            import json

            # print(json.dumps(version, indent=2))
            print("\n\tversion = \n{}\n".format(json.dumps(version, indent=2)))

        # fixed_version_ranges, affected_version_ranges = self.to_version_ranges(versions_data)

        fixed_version = []

        for entry in data["timeline"]:
            value = entry["value"]
            # if "released" in entry["value"]:
            if "released" in value:
                # fixed_version.append(entry["value"])
                fixed_version.append(value.split(" ")[0])

        affected_packages = []
        # fixed_packages = []

        for version in versions_data:
            affected_package = AffectedPackage(
                package=PackageURL(
                    type="generic",
                    name="apache_httpd",
                ),
                # affected_version_range=affected_version_range,
                affected_version_range=version.get("version_value", "ERROR!!"),
                fixed_version=fixed_version[0],
                # fixed_version="to come",
            )
            affected_packages.append(affected_package)

        # for version_range in fixed_version_ranges:
        #     fixed_packages.extend(
        #         [
        #             PackageURL(type="apache", name="httpd", version=version)
        #             for version in self.version_api.get("apache/httpd").valid_versions
        #             if SemverVersion(version) in version_range
        #         ]
        #     )

        # for version_range in affected_version_ranges:
        #     affected_packages.extend(
        #         [
        #             PackageURL(type="apache", name="httpd", version=version)
        #             for version in self.version_api.get("apache/httpd").valid_versions
        #             if SemverVersion(version) in version_range
        #         ]
        #     )

        return AdvisoryData(
            # vulnerability_id=cve,
            aliases=[alias],
            summary=description,
            # affected_packages=nearest_patched_package(affected_packages, fixed_packages),
            affected_packages=affected_packages,
            references=[reference],
        )

    # def to_version_ranges(self, versions_data):
    #     fixed_version_ranges = []
    #     affected_version_ranges = []
    #     for version_data in versions_data:
    #         version_value = version_data["version_value"]
    #         range_expression = version_data["version_affected"]
    #         if range_expression == "<":
    #             fixed_version_ranges.append(
    #                 VersionRange.from_scheme_version_spec_string(
    #                     "semver", ">={}".format(version_value)
    #                 )
    #             )
    #         elif range_expression == "=" or range_expression == "?=":
    #             affected_version_ranges.append(
    #                 VersionRange.from_scheme_version_spec_string(
    #                     "semver", "{}".format(version_value)
    #                 )
    #             )

    #     return (fixed_version_ranges, affected_version_ranges)


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
