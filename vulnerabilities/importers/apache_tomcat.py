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
import dataclasses
import re


import requests
from bs4 import BeautifulSoup
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import create_etag
from vulnerabilities.package_managers import MavenVersionAPI


@dataclasses.dataclass
class ApacheTomcatDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


class ApacheTomcatDataSource(DataSource):

    CONFIG_CLASS = ApacheTomcatDataSourceConfiguration
    base_url = "https://tomcat.apache.org/security-{}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.version_api = MavenVersionAPI()
        asyncio.run(self.version_api.load_api({"org.apache.tomcat:tomcat"}))

    def updated_advisories(self):
        advisories = []
        for advisory_page in self.fetch_pages():
            advisories.extend(self.to_advisories(advisory_page))
        return self.batch_advisories(advisories)

    def fetch_pages(self):
        tomcat_major_versions = {i[0] for i in self.version_api.get("org.apache.tomcat:tomcat")}
        for version in tomcat_major_versions:
            page_url = self.base_url.format(version)
            if create_etag(self, page_url, "ETag"):
                yield requests.get(page_url).content

    def to_advisories(self, apache_tomcat_advisory_html):
        advisories = []
        page_soup = BeautifulSoup(apache_tomcat_advisory_html, features="lxml")
        pageh3s = page_soup.find_all("h3")
        vuln_headings = [i for i in pageh3s if "Fixed in Apache Tomcat" in i.text]
        for data in vuln_headings:
            fixed_version = data.text.split("Fixed in Apache Tomcat")[-1].strip()
            details_div = data.find_next_sibling()

            for anchor_tag in details_div.find_all("a"):
                if "cve.mitre.org" not in anchor_tag["href"]:
                    continue

                cve_id = re.search(r"CVE-\d*-\d*", anchor_tag.text).group()
                references = []
                affected_packages = []
                paragraph = anchor_tag.find_parent()

                while paragraph and "Affects:" not in paragraph.text:
                    for ref in paragraph.find_all("a"):
                        references.append(Reference(url=ref["href"]))

                    paragraph = paragraph.find_next_sibling()

                if not paragraph:
                    # At the end of details_div
                    continue

                for version_range in parse_version_ranges(paragraph.text):
                    affected_packages.extend(
                        [
                            PackageURL(
                                type="maven", namespace="apache", name="tomcat", version=version
                            )
                            for version in self.version_api.get("org.apache.tomcat:tomcat")
                            if version in version_range
                        ]
                    )

                fixed_package = [
                    PackageURL(
                        type="maven", namespace="apache", name="tomcat", version=fixed_version
                    )
                ]

                advisories.append(
                    Advisory(
                        summary="",
                        impacted_package_urls=affected_packages,
                        resolved_package_urls=fixed_package,
                        vulnerability_id=cve_id,
                        references=references,
                    )
                )

        return advisories


def parse_version_ranges(string):
    """
    This method yields Rangespecifier objects obtained by
    parsing `string`.
    >> list(parse_version_ranges("Affects: 9.0.0.M1 to 9.0.0.M9"))
    [RangeSpecifier(<=9.0.0.M9,>=9.0.0.M1)]

    >> list(parse_version_ranges("Affects: 9.0.0.M1"))
    [RangeSpecifier(>=9.0.0.M1<=9.0.0.M1)]

    >> list(parse_version_ranges("Affects: 9.0.0.M1 to 9.0.0.M9, 1.2.3 to 3.4.5"))
    [RangeSpecifier(<=9.0.0.M9,>=9.0.0.M1), RangeSpecifier(<=3.4.5,>=1.2.3)]
    """
    version_rng_txt = string.split("Affects:")[-1].strip()
    version_ranges = version_rng_txt.split(",")
    for version_range in version_ranges:
        if "to" in version_range:
            lower_bound, upper_bound = version_range.split("to")
        elif "-" in version_range and not any([i.isalpha() for i in version_range]):
            lower_bound, upper_bound = version_range.split("-")
        else:
            lower_bound = upper_bound = version_range

        yield RangeSpecifier(">=" + lower_bound + "<=" + upper_bound)
