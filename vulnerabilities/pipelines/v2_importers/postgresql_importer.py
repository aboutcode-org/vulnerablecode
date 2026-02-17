#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import urllib.parse as urlparse
from typing import Iterable

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import GenericVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class PostgreSQLImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    PostgreSQL Importer Pipeline

    This pipeline imports security advisories from the PostgreSQL project.
    """

    pipeline_id = "postgresql_importer_v2"
    license_url = "https://www.postgresql.org/about/licence/"
    spdx_license_expression = "PostgreSQL"
    base_url = "https://www.postgresql.org/support/security/"

    links = set()

    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        return 30

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        url = "https://www.postgresql.org/support/security/"

        data = requests.get(url).content
        yield from self.to_advisories(data, url)

    def collect_links(self):
        known_urls = {self.base_url}
        visited_urls = set()

        while True:
            unvisited_urls = known_urls - visited_urls
            for url in unvisited_urls:
                data = requests.get(url).content
                visited_urls.add(url)
                known_urls.update(self.find_advisory_urls(data))
            if known_urls == visited_urls:
                break
        self.links = known_urls

    def to_advisories(self, data, url):
        advisories = []
        soup = BeautifulSoup(data, features="lxml")
        tables = soup.select("table")

        if not tables:
            return advisories

        table = tables[0]

        for row in table.select("tbody tr"):
            ref_col, affected_col, fixed_col, severity_score_col, desc_col = row.select("td")
            summary = desc_col.text
            pkg_qualifiers = {"os": "windows"} if "windows" in summary.lower() else {}

            affected_packages = []
            affected_version_list = [v.strip() for v in affected_col.text.split(",") if v.strip()]
            fixed_version_list = [v.strip() for v in fixed_col.text.split(",") if v.strip()]
            fixed_version_range = (
                GenericVersionRange.from_versions(fixed_version_list)
                if fixed_version_list
                else None
            )
            affected_version_range = (
                GenericVersionRange.from_versions(affected_version_list)
                if affected_version_list
                else None
            )

            if affected_version_range or fixed_version_range:
                affected_packages.append(
                    AffectedPackageV2(
                        package=PackageURL(
                            name="postgresql", type="generic", qualifiers=pkg_qualifiers
                        ),
                        affected_version_range=affected_version_range,
                        fixed_version_range=fixed_version_range,
                    )
                )

            cve_id = ""
            try:
                cve_id = ref_col.select(".nobr")[0].text
            except IndexError:
                pass

            references = []
            severities = []
            vector_link_tag = severity_score_col.find("a")
            for a_tag in ref_col.select("a"):
                link = a_tag.attrs["href"]
                if link.startswith("/"):
                    link = urlparse.urljoin("https://www.postgresql.org/", link)
                if "support/security/CVE" in link and vector_link_tag:
                    parsed_link = urlparse.urlparse(vector_link_tag["href"])
                    cvss3_vector = urlparse.parse_qs(parsed_link.query).get("vector", [""])[0]
                    cvss3_base_score = vector_link_tag.text
                    severities.append(
                        VulnerabilitySeverity(
                            system=severity_systems.CVSSV3,
                            value=cvss3_base_score,
                            scoring_elements=cvss3_vector,
                        )
                    )
                references.append(ReferenceV2(url=link))

            if cve_id:
                advisories.append(
                    AdvisoryDataV2(
                        advisory_id=cve_id,
                        aliases=[],
                        summary=summary,
                        references=references,
                        severities=severities,
                        affected_packages=affected_packages,
                        url=url,
                        original_advisory_text=str(row),
                    )
                )

        return advisories

    def find_advisory_urls(self, page_data):
        soup = BeautifulSoup(page_data, features="lxml")
        return {
            urlparse.urljoin("https://www.postgresql.org/", a_tag.attrs["href"])
            for a_tag in soup.select("h3+ p a")
        }
