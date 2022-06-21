#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import asyncio
import re

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.utils import create_etag
from vulnerabilities.utils import nearest_patched_package


class ApacheTomcatImporter(Importer):

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
        # Here Semver is used because it has notion of major, minor versions.
        tomcat_major_versions = {
            SemverVersion(i).value.major
            for i in self.version_api.get("org.apache.tomcat:tomcat").valid_versions
        }
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
                            for version in self.version_api.get(
                                "org.apache.tomcat:tomcat"
                            ).valid_versions
                            if MavenVersion(version) in version_range
                        ]
                    )

                fixed_package = [
                    PackageURL(
                        type="maven", namespace="apache", name="tomcat", version=fixed_version
                    )
                ]

                advisories.append(
                    AdvisoryData(
                        summary="",
                        affected_packages=nearest_patched_package(affected_packages, fixed_package),
                        vulnerability_id=cve_id,
                        references=references,
                    )
                )

        return advisories


def parse_version_ranges(string):
    """
    This method yields VersionRange objects obtained by
    parsing `string`.
    >>> list(parse_version_ranges("Affects: 9.0.0.M1 to 9.0.0.M9")) == [
    ...     VersionRange.from_scheme_version_spec_string('maven','<=9.0.0.M9,>=9.0.0.M1')
    ...  ]
    True
    >>> list(parse_version_ranges("Affects: 9.0.0.M1")) == [
    ...     VersionRange.from_scheme_version_spec_string('maven','>=9.0.0.M1,<=9.0.0.M1')
    ...  ]
    True
    >>> list(parse_version_ranges("Affects: 9.0.0.M1 to 9.0.0.M9, 1.2.3 to 3.4.5")) == [
    ...     VersionRange.from_scheme_version_spec_string('maven','<=9.0.0.M9,>=9.0.0.M1'),
    ...     VersionRange.from_scheme_version_spec_string('maven','<=3.4.5,>=1.2.3')
    ...  ]
    True
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

        yield MavenVersionRange.from_native(f">={lower_bound},<={upper_bound}")
