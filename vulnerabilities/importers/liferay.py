#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import VulnerabilityReference


class LiferayImporter(Importer):
    """
    Importer for Liferay advisories.
    """
    spdx_license_identifier = "CC-BY-SA-4.0"  # License for Liferay's data

    def fetch(self):
        """
        Fetches the HTML content from the Liferay Known Vulnerabilities page.
        """
        url = "https://liferay.dev/portal/security/known-vulnerabilities"
        response = requests.get(url)
        response.raise_for_status()
        return response.text

    def parse(self, html):
        """
        Parses the fetched HTML and extracts vulnerability data.
        Returns a list of AdvisoryData objects.
        """
        soup = BeautifulSoup(html, "html.parser")
        advisories = []

        # Locate the table. (Adjust the selector if the page structure changes.)
        table = soup.find("table")
        if not table:
            return advisories

        # Iterate over each row in the table body.
        tbody = table.find("tbody")
        if not tbody:
            return advisories

        for row in tbody.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) < 5:
                continue  

            # Extract each field by cell order.
            vulnerability_id = cells[0].get_text(strip=True)
            affected_versions = cells[1].get_text(strip=True)
            description = cells[2].get_text(strip=True)
            severity = cells[3].get_text(strip=True)

            # Extract references – there may be multiple links in the cell.
            references = []
            for a in cells[4].find_all("a", href=True):
                ref_url = a["href"].strip()
                if ref_url:
                    references.append(VulnerabilityReference(url=ref_url))

            # Create PackageURL objects for affected versions.
            affected_packages = []
            for version in affected_versions.split(","):
                version = version.strip()
                if version:
                    affected_packages.append(
                        PackageURL(
                            type="liferay",  
                            name="liferay-portal",  
                            version=version,
                        )
                    )

            # Create an AdvisoryData object.
            advisories.append(
                AdvisoryData(
                    aliases=[vulnerability_id],
                    summary=description,
                    affected_packages=affected_packages,
                    references=references,
                    severity=severity,
                )
            )

        return advisories

    def advisory_data(self):
        """
        Fetches and parses the data, returning a list of AdvisoryData objects.
        """
        html = self.fetch()
        return self.parse(html)