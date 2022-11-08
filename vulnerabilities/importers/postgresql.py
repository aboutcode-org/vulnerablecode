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
from univers.version_range import GenericVersionRange
from univers.versions import GenericVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity


class PostgreSQLImporter(Importer):

    root_url = "https://www.postgresql.org/support/security/"
    license_url = "https://www.postgresql.org/about/licence/"
    spdx_license_expression = "PostgreSQL"

    def advisory_data(self):
        known_urls = {self.root_url}
        visited_urls = set()
        data_by_url = {}
        while True:
            unvisited_urls = known_urls - visited_urls
            for url in unvisited_urls:
                data = requests.get(url).content
                data_by_url[url] = data
                visited_urls.add(url)
                known_urls.update(find_advisory_urls(data))

            if known_urls == visited_urls:
                break

        for url, data in data_by_url.items():
            yield from to_advisories(data)


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

        affected_packages = []
        affected_version_list = affected_col.text.split(",")
        fixed_version_list = fixed_col.text.split(",")

        if fixed_version_list:
            for fixed_version in fixed_version_list:
                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(
                            name="postgresql",
                            # TODO: See https://github.com/nexB/vulnerablecode/issues/990
                            type="generic",
                            qualifiers=pkg_qualifiers,
                        ),
                        affected_version_range=GenericVersionRange.from_versions(
                            affected_version_list
                        )
                        if affected_version_list
                        else None,
                        fixed_version=GenericVersion(fixed_version) if fixed_version else None,
                    )
                )
        elif affected_version_list:
            affected_packages.append(
                AffectedPackage(
                    package=PackageURL(
                        name="postgresql",
                        # TODO: See https://github.com/nexB/vulnerablecode/issues/990
                        type="generic",
                        qualifiers=pkg_qualifiers,
                    ),
                    affected_version_range=GenericVersionRange.from_versions(affected_version_list),
                )
            )
        cve_id = ""
        try:
            cve_id = ref_col.select(".nobr")[0].text
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
                    severity = VulnerabilitySeverity(
                        system=severity_systems.CVSSV3,
                        value=cvss3_base_score,
                        scoring_elements=cvss3_vector,
                    )
                    severities.append(severity)
            references.append(Reference(url=link, severities=severities))
        if cve_id:
            advisories.append(
                AdvisoryData(
                    aliases=[cve_id],
                    summary=summary,
                    references=references,
                    affected_packages=affected_packages,
                )
            )
    return advisories


def find_advisory_urls(page_data):
    soup = BeautifulSoup(page_data, features="lxml")
    return {
        urlparse.urljoin("https://www.postgresql.org/", a_tag.attrs["href"])
        for a_tag in soup.select("h3+ p a")
    }
