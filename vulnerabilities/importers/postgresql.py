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
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import dataclasses

from bs4 import BeautifulSoup
from packageurl import PackageURL
import requests
from urllib.parse import urljoin

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Reference

BASE_URL = "https://www.postgresql.org/"


class PostgreSQLDataSource(DataSource):

    root_url = "https://www.postgresql.org/support/security/"

    def updated_advisories(self):
        advisories = []
        known_urls = {self.root_url}
        visited_urls = set()
        while True:
            unvisited_urls = known_urls - visited_urls
            for url in unvisited_urls:
                data = requests.get(url).content
                advisories.extend(to_advisories(data))
                visited_urls.add(url)
                known_urls.update(find_advisory_urls(data))

            if known_urls == visited_urls:
                break

        return self.batch_advisories(advisories)


def to_advisories(data):
    advisories = []
    soup = BeautifulSoup(data)
    table = soup.select("table")[0]
    for row in table.select("tbody tr"):
        ref_col, affected_col, fixed_col, severity_score_col, desc_col = row.select("td")
        summary = desc_col.text
        pkg_qualifiers = {}
        if "windows" in summary.lower():
            pkg_qualifiers = {"os": "windows"}

        affected_packages = [
            PackageURL(
                type="generic",
                name="postgresql",
                version=version.strip(),
                qualifiers=pkg_qualifiers,
            )
            for version in affected_col.text.split(",")
        ]

        fixed_packages = [
            PackageURL(
                type="generic",
                name="postgresql",
                version=version.strip(),
                qualifiers=pkg_qualifiers,
            )
            for version in fixed_col.text.split(",")
        ]

        try:
            cve_id = ref_col.select("nobr")[0].text
            # This is for the anomaly in https://www.postgresql.org/support/security/8.1/ 's
            # last entry
        except IndexError:
            pass

        references = []
        for a_tag in ref_col.select("a"):
            link = a_tag.attrs["href"]
            if link.startswith("/about/news/"):
                # Convert postgresql official announcements to absolute url.
                link = urljoin(BASE_URL, link)

            references.append(Reference(url=link))

        advisories.append(
            Advisory(
                vulnerability_id=cve_id,
                summary=summary,
                vuln_references=references,
                impacted_package_urls=affected_packages,
                resolved_package_urls=fixed_packages,
            )
        )

    return advisories


def find_advisory_urls(page_data):
    soup = BeautifulSoup(page_data)
    return {urljoin(BASE_URL, a_tag.attrs["href"]) for a_tag in soup.select("h3+ p a")}
