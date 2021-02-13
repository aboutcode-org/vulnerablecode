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

import requests
from bs4 import BeautifulSoup
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import GitHubTagsAPI

GH_PAGE_URL = "https://raw.githubusercontent.com/apache/kafka-site/asf-site/cve-list.html"
ASF_PAGE_URL = "https://kafka.apache.org/cve-list"


class ApacheKafkaDataSource(DataSource):
    @staticmethod
    def fetch_advisory_page():
        page = requests.get(GH_PAGE_URL)
        return page.content

    def set_api(self):
        self.version_api = GitHubTagsAPI()
        asyncio.run(self.version_api.load_api(["apache/kafka"]))

    def updated_advisories(self):
        advisory_page = self.fetch_advisory_page()
        self.set_api()
        parsed_data = self.to_advisory(advisory_page)
        return self.batch_advisories(parsed_data)

    def to_advisory(self, advisory_page):
        advisories = []
        advisory_page = BeautifulSoup(advisory_page, features="lxml")
        cve_section_beginnings = advisory_page.find_all("h2")
        for cve_section_beginning in cve_section_beginnings:
            cve_id = cve_section_beginning.text.split("\n")[0]
            cve_description_paragraph = cve_section_beginning.find_next_sibling("p")
            cve_data_table = cve_section_beginning.find_next_sibling("table")
            cve_data_table_rows = cve_data_table.find_all("tr")
            affected_versions_row = cve_data_table_rows[0]
            fixed_versions_row = cve_data_table_rows[1]
            affected_version_ranges = to_version_ranges(
                affected_versions_row.find_all("td")[1].text
            )
            fixed_version_ranges = to_version_ranges(fixed_versions_row.find_all("td")[1].text)

            fixed_packages = [
                PackageURL(type="apache", name="kafka", version=version)
                for version in self.version_api.get("apache/kafka")
                if any([version in version_range for version_range in fixed_version_ranges])
            ]

            affected_packages = [
                PackageURL(type="apache", name="kafka", version=version)
                for version in self.version_api.get("apache/kafka")
                if any([version in version_range for version_range in affected_version_ranges])
            ]

            advisories.append(
                Advisory(
                    cve_id=cve_id,
                    summary=cve_description_paragraph.text,
                    impacted_package_urls=affected_packages,
                    resolved_package_urls=fixed_packages,
                    vuln_references=[
                        Reference(url=ASF_PAGE_URL),
                        Reference(
                            url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                            reference_id=cve_id,
                        ),
                    ],
                )
            )
        return advisories


def to_version_ranges(version_range_text):
    version_ranges = []
    range_expressions = version_range_text.split(",")
    for range_expression in range_expressions:
        if "to" in range_expression:
            # eg range_expression == "3.2.0 to 3.2.1"
            lower_bound, upper_bound = range_expression.split("to")
            lower_bound = f">={lower_bound}"
            upper_bound = f"<={upper_bound}"
            version_ranges.append(RangeSpecifier(f"{lower_bound},{upper_bound}"))

        elif "and later" in range_expression:
            # eg range_expression == "2.1.1 and later"
            range_expression = range_expression.replace("and later", "")
            version_ranges.append(RangeSpecifier(f">={range_expression}"))

        else:
            # eg  range_expression == "3.0.0"
            version_ranges.append(RangeSpecifier(range_expression))
    return version_ranges
