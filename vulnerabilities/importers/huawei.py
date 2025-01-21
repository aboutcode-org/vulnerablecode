#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import GenericVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HuaweiImporter(Importer):
    root_url = "https://consumer.huawei.com/en/support/bulletin/"
    spdx_license_expression = "NOASSERTION"
    importer_name = "Huawei Security Bulletin Importer"

    def advisory_data(self):
        years_months = [
            ("2024", range(7, 13)),  # July 2024 to December 2024
            ("2025", range(1, 2)),  # January 2025
        ]
        for year, months in years_months:
            for month in months:
                url = f"{self.root_url}{year}/{month}/"
                try:
                    response = requests.get(url)
                    response.raise_for_status()
                    yield from self.to_advisories(response.content, url)
                except requests.RequestException as e:
                    logger.error(f"Failed to fetch URL {url}: {e}")
                    continue

    def parse_version(self, version_str):
        """Parse version string and separate OS type and version number."""
        version_str = version_str.strip()

        harmony_match = re.match(r"HarmonyOS\s*(\d+\.\d+\.\d+)", version_str)
        if harmony_match:
            return "harmony", harmony_match.group(1)

        emui_match = re.match(r"EMUI\s*(\d+\.\d+\.\d+)", version_str)
        if emui_match:
            return "emui", emui_match.group(1)

        return None, None

    def group_versions_by_os(self, versions):
        """Group versions by OS type."""
        grouped = {"harmony": [], "emui": []}

        for version in versions:
            os_type, version_num = self.parse_version(version)
            if os_type and version_num:
                grouped[os_type].append(version_num)
            else:
                logger.warning(f"Skipping unparseable version: {version}")

        return grouped

    def create_affected_packages(self, os_type, versions, fixed=False):
        """Create AffectedPackage objects for a given OS type and versions."""
        if not versions:
            return []

        package = PackageURL(
            name=os_type,
            type="generic",
        )

        if fixed:
            return [
                AffectedPackage(package=package, fixed_version=GenericVersion(version))
                for version in versions
            ]
        else:
            return [
                AffectedPackage(
                    package=package,
                    affected_version_range=GenericVersionRange.from_versions(versions),
                )
            ]

    def to_advisories(self, content, url):
        soup = BeautifulSoup(content, features="lxml")
        tables = soup.find_all("table")
        if len(tables) < 2:
            logger.warning(f"Expected at least 2 tables, found {len(tables)} at {url}")
            return

        affected_table = tables[0]
        fixed_table = tables[1]
        cve_data = {}

        for row in affected_table.find_all("tr"):
            cols = row.find_all("td")
            if len(cols) >= 5:
                cve_id = cols[0].text.strip()
                versions = [v.strip() for v in cols[4].text.strip().split(",") if v.strip()]
                grouped_versions = self.group_versions_by_os(versions)

                if cve_id not in cve_data:
                    cve_data[cve_id] = {
                        "affected_versions": grouped_versions,
                        "fixed_versions": {"harmony": [], "emui": []},
                    }
                else:
                    for os_type in grouped_versions:
                        cve_data[cve_id]["affected_versions"][os_type].extend(
                            grouped_versions[os_type]
                        )

        for row in fixed_table.find_all("tr"):
            cols = row.find_all("td")
            if len(cols) >= 3:
                cve_id = cols[0].text.strip()
                versions = [v.strip() for v in cols[2].text.strip().split(",") if v.strip()]
                grouped_versions = self.group_versions_by_os(versions)

                if cve_id not in cve_data:
                    cve_data[cve_id] = {
                        "affected_versions": {"harmony": [], "emui": []},
                        "fixed_versions": grouped_versions,
                    }
                else:
                    for os_type in grouped_versions:
                        cve_data[cve_id]["fixed_versions"][os_type].extend(
                            grouped_versions[os_type]
                        )

        for cve_id, data in cve_data.items():
            affected_packages = []

            affected_packages.extend(
                self.create_affected_packages("harmony", data["affected_versions"]["harmony"])
            )
            affected_packages.extend(
                self.create_affected_packages(
                    "harmony", data["fixed_versions"]["harmony"], fixed=True
                )
            )

            affected_packages.extend(
                self.create_affected_packages("emui", data["affected_versions"]["emui"])
            )
            affected_packages.extend(
                self.create_affected_packages("emui", data["fixed_versions"]["emui"], fixed=True)
            )

            if affected_packages:
                yield AdvisoryData(
                    aliases=[cve_id],
                    summary="",
                    references=[],
                    affected_packages=affected_packages,
                    url=url,
                )
