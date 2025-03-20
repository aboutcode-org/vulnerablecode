#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Iterable

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline


class ZDIImporterPipeline(VulnerableCodeBaseImporterPipeline):
    pipeline_id = "zdi_importer"

    spdx_license_expression = "LicenseRef-ZDI-Terms-Of-Use"
    importer_name = "Zero Day Initiative Importer"

    url = "https://www.zerodayinitiative.com/advisories/published/"

    @classmethod
    def steps(cls):
        return (
            cls.fetch_advisories,
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    def fetch_advisories(self):
        self.log(f"Fetching advisories from {self.url}")
        response = requests.get(self.url)
        if response.status_code != 200:
            self.log(f"Failed to fetch advisories: {response.status_code}", level=logging.ERROR)
            return
        self.advisory_data = response.text

        html_snippet = (
            self.advisory_data[:1000] + "..."
            if len(self.advisory_data) > 1000
            else self.advisory_data
        )
        self.log(f"Received HTML snippet: {html_snippet}", level=logging.DEBUG)

    def advisories_count(self):
        if not hasattr(self, "advisory_data"):
            return 0

        soup = BeautifulSoup(self.advisory_data, features="lxml")
        table = soup.find("table", id="publishedAdvisories")
        if not table:
            return 0

        rows = table.find_all("tr")
        return max(0, len(rows) - 1)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        if not hasattr(self, "advisory_data"):
            self.log("No advisory data available", level=logging.ERROR)
            return []

        soup = BeautifulSoup(self.advisory_data, features="lxml")

        table = soup.find("table", id="publishedAdvisories")

        if not table:
            self.log("Could not find table by ID, trying alternative selectors", level=logging.INFO)
            tables = soup.find_all("table")
            self.log(f"Found {len(tables)} tables on the page", level=logging.INFO)

            for idx, potential_table in enumerate(tables):
                headers = potential_table.find_all("th")
                header_text = [h.text.strip() for h in headers if h.text.strip()]
                self.log(f"Table {idx} headers: {header_text}", level=logging.DEBUG)

                if any(
                    keyword in " ".join(header_text).lower()
                    for keyword in ["zdi", "cve", "advisory", "vulnerability", "published"]
                ):
                    table = potential_table
                    self.log(f"Selected table {idx} based on headers", level=logging.INFO)
                    break

        if not table:
            self.log("Could not find advisories table", level=logging.ERROR)
            return []

        rows = table.find_all("tr")
        self.log(f"Found {len(rows)} rows in table", level=logging.INFO)

        if not rows:
            return []

        first_row = rows[0]
        is_header = first_row.find_all("th")

        data_rows = rows[1:] if is_header else rows

        for row in data_rows:
            cells = row.find_all("td")
            if not cells:
                continue

            try:
                cell_texts = [c.text.strip() for c in cells]

                zdi_id = None
                title = None
                vendor = None
                product = None
                cve = None

                for idx, cell in enumerate(cells):
                    text = cell.text.strip()

                    if (text.startswith("ZDI-") or text.startswith("ZDI-CAN-")) and not zdi_id:
                        zdi_id = text
                    elif text.startswith("CVE-") and not cve:
                        cve = text
                    elif len(text) > 20 and not title:
                        title = text
                    elif len(text) < 20:
                        if not vendor:
                            vendor = text
                        elif not product:
                            product = text

                if len(cells) >= 6:
                    if not zdi_id:
                        zdi_id = cells[0].text.strip()
                    if not title:
                        title = cells[1].text.strip()
                    if not vendor:
                        vendor = cells[2].text.strip()
                    if not product:
                        product = cells[3].text.strip()
                    if not cve:
                        cve = cells[5].text.strip()

                if not zdi_id or not title:
                    self.log("Skipping row with insufficient data", level=logging.DEBUG)
                    continue

                advisory_url = f"https://www.zerodayinitiative.com/advisories/{zdi_id}/"

                references = [
                    Reference(
                        reference_id=zdi_id,
                        url=advisory_url,
                    )
                ]

                aliases = [zdi_id]
                if cve and cve.startswith("CVE-"):
                    aliases.append(cve)

                affected_packages = []
                if vendor and product:
                    affected_packages.append(
                        AffectedPackage(
                            package=PackageURL(
                                type="generic",
                                name=product,
                                namespace=vendor,
                            ),
                            affected_version_range="vers:*",
                        )
                    )

                yield AdvisoryData(
                    summary=title,
                    references=references,
                    affected_packages=affected_packages,
                    aliases=aliases,
                    url=advisory_url,
                )

            except Exception as e:
                self.log(f"Error processing advisory row: {e}", level=logging.ERROR)
                import traceback

                self.log(traceback.format_exc(), level=logging.DEBUG)
