#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
import re
import urllib
from collections import defaultdict
from collections import namedtuple
from typing import Iterable

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import ApacheVersionRange
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class ApacheTomcatImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Apache HTTPD Importer Pipeline

    This pipeline imports security advisories from the Apache HTTPD project.
    """

    pipeline_id = "apache_tomcat_importer_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"
    base_url = "https://tomcat.apache.org/security"

    def fetch_advisory_links(self):
        """
        Yield the URLs of each Tomcat version security-related page.
        Each page link is in the form of `https://tomcat.apache.org/security-10.html`,
        for instance, for v10.
        """
        data = requests.get(self.base_url).content
        soup = BeautifulSoup(data, features="lxml")
        for tag in soup.find_all("a"):
            link = tag.get("href")

            if link and "security-" in link and any(char.isdigit() for char in link):
                yield urllib.parse.urljoin(self.base_url, link)

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    @classmethod
    def advisories_count(cls):
        return 0

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for page_url in self.fetch_advisory_links():
            try:
                content = requests.get(page_url).content
                tomcat_advisories = parse_tomcat_security(content)
                self.log(f"Processing {len(tomcat_advisories)} advisories from {page_url}")
                grouped = defaultdict(list)
                for advisory in tomcat_advisories:
                    grouped[advisory.cve].append(advisory)
                for cve, advisory_list in grouped.items():
                    affected_packages = []
                    for advisory in advisory_list:
                        self.log(f"Processing advisory {advisory.cve}")
                        apache_range = to_version_ranges_apache(
                            advisory.affected_versions,
                            advisory.fixed_in,
                            self,
                        )

                        maven_range = to_version_ranges_maven(
                            advisory.affected_versions,
                            advisory.fixed_in,
                        )

                        affected_packages.append(
                            AffectedPackageV2(
                                package=PackageURL(type="apache", name="tomcat"),
                                affected_version_range=apache_range,
                            )
                        )

                        affected_packages.append(
                            AffectedPackageV2(
                                package=PackageURL(
                                    type="maven",
                                    namespace="org.apache.tomcat",
                                    name="tomcat",
                                ),
                                affected_version_range=maven_range,
                            )
                        )
                    page_id = page_url.split("/")[-1].replace(".html", "")
                    yield AdvisoryData(
                        advisory_id=f"{page_id}/{cve}",
                        summary=advisory_list[0].summary,
                        affected_packages=affected_packages,
                        url=page_url,
                    )

            except Exception as e:
                self.log(f"{e!r}")


def to_version_ranges_apache(version_item, fixed_version, self=None):
    constraints = []

    VersionConstraintTuple = namedtuple("VersionConstraintTuple", ["comparator", "version"])
    affected_constraint_tuple_list = []
    fixed_constraint_tuple_list = []

    if version_item:
        version_item = version_item.strip()
        if "to" in version_item:
            version_item_split = version_item.split(" ")
            affected_constraint_tuple_list.append(
                VersionConstraintTuple(">=", version_item_split[0])
            )
            affected_constraint_tuple_list.append(
                VersionConstraintTuple("<=", version_item_split[-1])
            )

        elif "-" in version_item:
            version_item_split = version_item.split("-")
            affected_constraint_tuple_list.append(
                VersionConstraintTuple(">=", version_item_split[0])
            )
            affected_constraint_tuple_list.append(
                VersionConstraintTuple("<=", version_item_split[-1])
            )

        elif version_item.startswith("<"):
            version_item_split = version_item.split("<")
            affected_constraint_tuple_list.append(
                VersionConstraintTuple("<", version_item_split[-1])
            )

        else:
            version_item_split = version_item.split(" ")
            affected_constraint_tuple_list.append(
                VersionConstraintTuple("=", version_item_split[0])
            )

    if fixed_version:
        fixed_item_split = fixed_version.split(" ")
        fixed_constraint_tuple_list.append(VersionConstraintTuple("=", fixed_item_split[0]))

    for record in affected_constraint_tuple_list:
        try:
            constraints.append(
                VersionConstraint(
                    comparator=record.comparator,
                    version=SemverVersion(record.version),
                )
            )
        except Exception as e:
            if self:
                self.log(f"{record.version!r} is not a valid SemverVersion {e!r}")
                continue

    for record in fixed_constraint_tuple_list:
        constraints.append(
            VersionConstraint(
                comparator=record.comparator,
                version=SemverVersion(record.version),
            ).invert()
        )

    return ApacheVersionRange(constraints=constraints)


def to_version_ranges_maven(version_item, fixed_version):
    constraints = []

    if version_item:
        version_item = version_item.strip()
        if "to" in version_item:
            version_item_split = version_item.split(" ")

            constraints.append(
                VersionConstraint(
                    comparator=">=",
                    version=MavenVersion(version_item_split[0]),
                )
            )
            constraints.append(
                VersionConstraint(
                    comparator="<=",
                    version=MavenVersion(version_item_split[-1]),
                )
            )

        elif "-" in version_item:
            version_item_split = version_item.split("-")

            constraints.append(
                VersionConstraint(
                    comparator=">=",
                    version=MavenVersion(version_item_split[0]),
                )
            )
            constraints.append(
                VersionConstraint(
                    comparator="<=",
                    version=MavenVersion(version_item_split[-1]),
                )
            )

        elif version_item.startswith("<"):
            version_item_split = version_item.split("<")

            constraints.append(
                VersionConstraint(
                    comparator="<",
                    version=MavenVersion(version_item_split[-1]),
                )
            )

        else:
            version_item_split = version_item.split(" ")

            constraints.append(
                VersionConstraint(
                    comparator="=",
                    version=MavenVersion(version_item_split[0]),
                )
            )

    if fixed_version:
        fixed_item_split = fixed_version.split(" ")

        constraints.append(
            VersionConstraint(
                comparator="=",
                version=MavenVersion(fixed_item_split[0]),
            ).invert()
        )

    return MavenVersionRange(constraints=constraints)


@dataclasses.dataclass(order=True)
class TomcatAdvisoryData:
    cve: str
    summary: str
    fixed_in: str
    affected_versions: str


def parse_tomcat_security(html_content):
    soup = BeautifulSoup(html_content, "lxml")
    results = []

    for header in soup.find_all("h3", id=re.compile(r"Fixed_in_Apache_Tomcat")):
        m = re.search(r"Tomcat\s+([\d\.]+)", header.get_text())
        if not m:
            continue
        fixed_in = m.group(1)

        container = header.find_next_sibling("div", class_="text")
        if not container:
            continue

        current = None

        for p in container.find_all("p", recursive=False):

            strong = p.find("strong")
            cve_link = p.find("a", href=re.compile(r"CVE-"))

            if strong and cve_link:
                if current:
                    results.append(current)

                current = {
                    "cve": cve_link.get_text(strip=True),
                    "summary": strong.get_text(" ", strip=True),
                    "affected_versions": None,
                    "fixed_in": fixed_in,
                }
                continue

            if current:
                text = p.get_text(" ", strip=True)
                if text.startswith("Affects:"):
                    current["affected_versions"] = text.replace("Affects:", "").strip()
                    current = TomcatAdvisoryData(
                        cve=current["cve"],
                        summary=current["summary"],
                        affected_versions=current["affected_versions"],
                        fixed_in=current["fixed_in"],
                    )
                    results.append(current)
                    current = None

        if current:
            current = TomcatAdvisoryData(
                cve=current["cve"],
                summary=current["summary"],
                affected_versions=current["affected_versions"],
                fixed_in=current["fixed_in"],
            )
            results.append(current)

    return results
