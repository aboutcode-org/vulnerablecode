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
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import CVSSV31
from vulnerabilities.utils import get_item

logger = logging.getLogger(__name__)


class LiferayImporter(Importer):
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"
    importer_name = "Liferay Importer"

    def advisory_data(self):
        """
        Yield AdvisoryData objects.
        """
        base_url = "https://liferay.dev/portal/security/known-vulnerabilities"
        
        # 1. Fetch Main Page
        try:
            main_page = requests.get(base_url)
            main_page.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch Liferay main page: {e}")
            return

        soup = BeautifulSoup(main_page.content, "lxml")
        
        # 2. Find Release Links
        # Based on analysis, releases are listed. We need to find links that look like release categories.
        # The structure seemed to be links under "Releases" section.
        # We'll look for links containing "/categories/" which seems to be the pattern for Liferay categories.
        release_links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "/categories/" in href and "known-vulnerabilities" in href:
                release_links.add(urljoin(base_url, href))

        for release_url in release_links:
            yield from self.process_release_page(release_url)

    def process_release_page(self, release_url):
        try:
            page = requests.get(release_url)
            page.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch release page {release_url}: {e}")
            return

        soup = BeautifulSoup(page.content, "lxml")
        
        # 3. Find Vulnerability Links
        # Vulnerabilities seem to be listed as links to "asset_publisher".
        vuln_links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "/asset_publisher/" in href and "cve-" in href.lower():
                vuln_links.add(urljoin(release_url, href))

        for vuln_url in vuln_links:
            yield from self.process_vulnerability_page(vuln_url)

    def process_vulnerability_page(self, vuln_url):
        try:
            page = requests.get(vuln_url)
            page.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch vulnerability page {vuln_url}: {e}")
            return

        soup = BeautifulSoup(page.content, "lxml")
        
        # Extract Details
        # Title usually contains CVE
        title = soup.find("h1")
        title_text = title.get_text(strip=True) if title else ""
        
        # CVE ID
        cve_match = re.search(r"(CVE-\d{4}-\d{4,})", title_text)
        if not cve_match:
            # Try to find in content
            cve_match = re.search(r"(CVE-\d{4}-\d{4,})", soup.get_text())
        
        cve_id = cve_match.group(1) if cve_match else ""
        if not cve_id:
            # If no CVE, we might skip or use a generated ID. For now, skip.
            return

        # Description
        description_header = soup.find(string=re.compile("Description"))
        description = ""
        if description_header:
            # Usually the description is in the next paragraph or sibling
            # The structure observed was <h3>Description</h3> <p>...</p>
            header_elem = description_header.parent
            if header_elem.name.startswith("h"):
                desc_elem = header_elem.find_next_sibling()
                if desc_elem:
                    description = desc_elem.get_text(strip=True)

        # Severity
        severity_header = soup.find(string=re.compile("Severity"))
        severities = []
        if severity_header:
            header_elem = severity_header.parent
            if header_elem.name.startswith("h"):
                sev_elem = header_elem.find_next_sibling()
                if sev_elem:
                    sev_text = sev_elem.get_text(strip=True)
                    # Example: 4.8 (CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N)
                    cvss_match = re.search(r"\(CVSS:3\.1/(.*?)\)", sev_text)
                    if cvss_match:
                        vector = cvss_match.group(1)
                        # We need to construct the full vector string if the library expects it, 
                        # or just pass the vector part. 
                        # VulnerabilitySeverity expects `scoring_elements` usually as the vector.
                        # And we need to calculate the score or use the one provided.
                        # Let's try to parse the score from text first.
                        score_match = re.match(r"([\d\.]+)", sev_text)
                        score = score_match.group(1) if score_match else None
                        
                        severities.append(
                            VulnerabilitySeverity(
                                system=CVSSV31,
                                value=score,
                                scoring_elements=f"CVSS:3.1/{vector}"
                            )
                        )

        # Affected Versions
        affected_header = soup.find(string=re.compile("Affected Version"))
        affected_packages = []
        if affected_header:
            header_elem = affected_header.parent
            if header_elem.name.startswith("h"):
                # Usually a list <ul> or just text
                next_elem = header_elem.find_next_sibling()
                if next_elem:
                    if next_elem.name == "ul":
                        items = next_elem.find_all("li")
                        for item in items:
                            pkg = self.parse_version_text(item.get_text(strip=True))
                            if pkg:
                                affected_packages.append(pkg)
                    else:
                        # Maybe just text lines?
                        lines = next_elem.get_text("\n").split("\n")
                        for line in lines:
                            pkg = self.parse_version_text(line.strip())
                            if pkg:
                                affected_packages.append(pkg)

        # Fixed Versions (Optional for now, but good to have)
        # ... (Implementation similar to affected versions if needed)

        yield AdvisoryData(
            aliases=[cve_id],
            summary=description,
            affected_packages=affected_packages,
            references=[Reference(url=vuln_url)],
            url=vuln_url
        )

    def parse_version_text(self, text):
        """
        Parse a string like "Liferay DXP 7.3 before update 14" into an AffectedPackage.
        """
        # Heuristic parsing
        if not text:
            return None
            
        # Determine package type/name
        if "DXP" in text:
            name = "liferay-dxp"
        elif "Portal" in text:
            name = "liferay-portal"
        else:
            name = "liferay-portal" # Default
            
        purl = PackageURL(type="generic", name=name)
        
        # Extract version
        # "7.3 before update 14" -> range
        # "7.4.0" -> exact
        
        # Simple regex for "X.Y.Z"
        version_match = re.search(r"(\d+\.\d+(\.\d+)?)", text)
        if version_match:
            version = version_match.group(1)
            try:
                # Treat as exact version for now
                affected_range = MavenVersionRange.from_versions([version])
                return AffectedPackage(
                    package=purl,
                    affected_version_range=affected_range
                )
            except Exception as e:
                logger.error(f"Failed to parse version {version}: {e}")
                return None
            
        return None
