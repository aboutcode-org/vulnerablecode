# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
from typing import Iterable

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from requests.exceptions import HTTPError
from requests.exceptions import RequestException
from requests.exceptions import Timeout

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline


class LiferayAdvisoryPipeline(VulnerableCodeBaseImporterPipeline):
    """Pipeline to import Liferay security advisories."""

    pipeline_id = "liferay_advisories"
    description = "Import Liferay security advisories"
    license_url = "https://liferay.dev/portal/security/known-vulnerabilities"
    spdx_license_expression = "CC-BY-4.0"
    importer_name = "Liferay Security Advisories"

    @classmethod
    def steps(cls):
        return (
            cls.fetch_advisories,
            cls.parse_advisories,
            cls.collect_and_store_advisories,  # Changed from collect_advisories
            cls.import_new_advisories,
        )

    def fetch_advisories(self):
        """Fetch HTML content from Liferay's security page."""
        try:
            response = requests.get(
                self.license_url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=30,
            )
            response.raise_for_status()
            self.html_content = response.text
            self.log(f"Response size: {len(self.html_content)} bytes")
        except (Timeout, HTTPError, RequestException) as e:
            self.log(f"Request error: {e}")
            raise
        except Exception as e:
            self.log(f"Unexpected error: {e}")
            raise

    def parse_advisories(self):
        """Parse HTML to extract advisories."""
        self.parsed_advisories = []
        soup = BeautifulSoup(self.html_content, "html.parser")

        # Look for CVE IDs anywhere in the page
        cve_patterns = soup.find_all(text=re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE))
        self.log(f"Found {len(cve_patterns)} potential CVE mentions")

        if not cve_patterns:
            self.log("No CVE IDs found in the page")
            return

        # Process each CVE mention
        processed_cves = set()
        for cve_text in cve_patterns:
            # Extract the CVE ID
            match = re.search(r"(CVE-\d{4}-\d+)", cve_text, re.IGNORECASE)
            if not match:
                continue

            cve_id = match.group(1).upper()
            if cve_id in processed_cves:
                continue

            processed_cves.add(cve_id)

            # Find the parent container
            parent = cve_text.parent
            container = None
            for _ in range(5):
                if not parent:
                    break
                if parent.name in ["article", "section", "div"] and len(parent.get_text()) > 100:
                    container = parent
                    break
                parent = parent.parent

            if not container:
                continue

            # Extract information
            try:
                # Description - get all text from paragraphs
                paragraphs = container.find_all("p")
                description = " ".join(p.get_text(strip=True) for p in paragraphs)

                # Affected versions
                affected_versions = []
                version_section = container.find(
                    text=re.compile(r"affected|versions", re.IGNORECASE)
                )

                if version_section:
                    version_list = None
                    parent = version_section.parent
                    for _ in range(3):
                        if not parent:
                            break
                        lists = parent.find_all(["ul", "ol"])
                        if lists:
                            version_list = lists[0]
                            break
                        parent = parent.parent

                    if version_list:
                        affected_versions = [
                            li.get_text(strip=True) for li in version_list.find_all("li")
                        ]

                # References - all links in the container
                references = []
                for a in container.find_all("a", href=True):
                    if a["href"].startswith("http"):
                        references.append(a["href"])

                self.parsed_advisories.append(
                    {
                        "cve_id": cve_id,
                        "summary": description[:500] if description else "",
                        "affected_versions": affected_versions,
                        "references": references,
                    }
                )

                self.log(f"Successfully parsed advisory for {cve_id}")

            except Exception as e:
                self.log(f"Error parsing advisory for {cve_id}: {e}")

    def parse_version_to_purl(self, version_text):
        """Convert version text to a PackageURL."""
        version_text = version_text.strip()
        if "DXP" in version_text.upper():
            match = re.search(r"\d+(?:\.\d+)*", version_text)
            if not match:
                raise ValueError(f"No version found in {version_text}")
            return PackageURL(type="liferay", name="dxp", version=match.group())
        else:
            match = re.search(r"\d+(?:\.\d+)*", version_text)
            if not match:
                raise ValueError(f"No version found in {version_text}")
            return PackageURL(type="liferay", name="portal", version=match.group())

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        """Generate advisory data from parsed content."""
        for advisory in self.parsed_advisories:
            affected_packages = []
            for version in advisory.get("affected_versions", []):
                try:
                    purl = self.parse_version_to_purl(version)
                    affected_packages.append(AffectedPackage(package=purl))
                except ValueError as e:
                    self.log(f"Skipping invalid version {version}: {e}")

            yield AdvisoryData(
                aliases=[advisory["cve_id"]],
                summary=advisory["summary"],
                references=[Reference(url=url) for url in advisory.get("references", [])],
                affected_packages=affected_packages,
                url=self.license_url,
            )

    def advisories_count(self):
        if hasattr(self, "parsed_advisories"):
            return len(self.parsed_advisories)
        return 0
