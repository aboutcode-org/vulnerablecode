# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import asyncio
import urllib

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.severity_systems import APACHE_HTTPD
from vulnerabilities.utils import nearest_patched_package


class ApacheHTTPDImporter(Importer):

    base_url = "https://httpd.apache.org/security/json/"

    def set_api(self):
        self.version_api = GitHubTagsAPI()
        asyncio.run(self.version_api.load_api(["apache/httpd"]))
        self.version_api.cache["apache/httpd"] = set(
            filter(
                lambda version: version.value not in ignore_tags,
                self.version_api.cache["apache/httpd"],
            )
        )

    def updated_advisories(self):
        links = fetch_links(self.base_url)
        self.set_api()
        advisories = []
        for link in links:
            data = requests.get(link).json()
            advisories.append(self.to_advisory(data))
        return self.batch_advisories(advisories)

    def to_advisory(self, data):
        cve = data["CVE_data_meta"]["ID"]
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
            reference_id=cve,
            url=urllib.parse.urljoin(self.base_url, f"{cve}.json"),
            severities=severities,
        )

        versions_data = []
        for vendor in data["affects"]["vendor"]["vendor_data"]:
            for products in vendor["product"]["product_data"]:
                for version_data in products["version"]["version_data"]:
                    versions_data.append(version_data)

        fixed_version_ranges, affected_version_ranges = self.to_version_ranges(versions_data)

        affected_packages = []
        fixed_packages = []

        for version_range in fixed_version_ranges:
            fixed_packages.extend(
                [
                    PackageURL(type="apache", name="httpd", version=version)
                    for version in self.version_api.get("apache/httpd").valid_versions
                    if SemverVersion(version) in version_range
                ]
            )

        for version_range in affected_version_ranges:
            affected_packages.extend(
                [
                    PackageURL(type="apache", name="httpd", version=version)
                    for version in self.version_api.get("apache/httpd").valid_versions
                    if SemverVersion(version) in version_range
                ]
            )

        return AdvisoryData(
            vulnerability_id=cve,
            summary=description,
            affected_packages=nearest_patched_package(affected_packages, fixed_packages),
            references=[reference],
        )

    def to_version_ranges(self, versions_data):
        fixed_version_ranges = []
        affected_version_ranges = []
        for version_data in versions_data:
            version_value = version_data["version_value"]
            range_expression = version_data["version_affected"]
            if range_expression == "<":
                fixed_version_ranges.append(
                    VersionRange.from_scheme_version_spec_string(
                        "semver", ">={}".format(version_value)
                    )
                )
            elif range_expression == "=" or range_expression == "?=":
                affected_version_ranges.append(
                    VersionRange.from_scheme_version_spec_string(
                        "semver", "{}".format(version_value)
                    )
                )

        return (fixed_version_ranges, affected_version_ranges)


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
