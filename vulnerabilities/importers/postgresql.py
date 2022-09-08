#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import urllib.parse as urlparse

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.utils import nearest_patched_package


class PostgreSQLImporter(Importer):

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
    soup = BeautifulSoup(data, features="lxml")
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
            if version
        ]

        try:
            cve_id = ref_col.select("nobr")[0].text
            # This is for the anomaly in https://www.postgresql.org/support/security/8.1/ 's
            # last entry
        except IndexError:
            pass

        references = []
        vector_link_tag = severity_score_col.find("a")
        for a_tag in ref_col.select("a"):
            link = a_tag.attrs["href"]
            if link.startswith("/"):
                # Convert relative urls to absolute url.
                # All links qualify this criteria, so this `if` statement is kind of a defensive mechanism
                link = urlparse.urljoin("https://www.postgresql.org/", link)
                severities = []
                if "support/security/CVE" in link and vector_link_tag:
                    parsed_link = urlparse.urlparse(vector_link_tag["href"])
                    cvss3_vector = urlparse.parse_qs(parsed_link.query)["vector"]
                    cvss3_base_score = vector_link_tag.text
                    severities.extend(
                        [
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV3, value=cvss3_base_score
                            ),
                            VulnerabilitySeverity(
                                system=severity_systems.CVSSV3_VECTOR, value=cvss3_vector
                            ),
                        ]
                    )
            references.append(Reference(url=link, severities=severities))

        advisories.append(
            AdvisoryData(
                vulnerability_id=cve_id,
                summary=summary,
                references=references,
                affected_packages=nearest_patched_package(affected_packages, fixed_packages),
            )
        )

    return advisories


def find_advisory_urls(page_data):
    soup = BeautifulSoup(page_data)
    return {
        urlparse.urljoin("https://www.postgresql.org/", a_tag.attrs["href"])
        for a_tag in soup.select("h3+ p a")
    }
