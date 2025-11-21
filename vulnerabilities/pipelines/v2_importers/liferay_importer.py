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
from typing import Iterable
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import MavenVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import CVSSV31

logger = logging.getLogger(__name__)


class LiferayImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"
    pipeline_id = "liferay_importer_v2"
    importer_name = "Liferay Importer"

    release_links = []

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        if not self.release_links:
            self.release_links = self.fetch_release_links()
        return len(self.release_links)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        if not self.release_links:
            self.release_links = self.fetch_release_links()

        for release_url in self.release_links:
            yield from self.process_release_page(release_url)

    def fetch_release_links(self):
        base_url = "https://liferay.dev/portal/security/known-vulnerabilities"
        try:
            main_page = requests.get(base_url)
            main_page.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch Liferay main page: {e}")
            return []

        soup = BeautifulSoup(main_page.content, "lxml")
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "/categories/" in href and "known-vulnerabilities" in href:
                links.add(urljoin(base_url, href))
        return list(links)

    def process_release_page(self, release_url):
        try:
            page = requests.get(release_url)
            page.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch release page {release_url}: {e}")
            return

        soup = BeautifulSoup(page.content, "lxml")
        
        # 3. Find Vulnerability Links
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
        title = soup.find("h1")
        title_text = title.get_text(strip=True) if title else ""
        
        # CVE ID
        cve_match = re.search(r"(CVE-\d{4}-\d{4,})", title_text)
        if not cve_match:
            cve_match = re.search(r"(CVE-\d{4}-\d{4,})", soup.get_text())
        
        cve_id = cve_match.group(1) if cve_match else ""
        if not cve_id:
            return

        # Description
        description_header = soup.find(string=re.compile("Description"))
        description = ""
        if description_header:
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
                    cvss_match = re.search(r"\(CVSS:3\.1/(.*?)\)", sev_text)
                    if cvss_match:
                        vector = cvss_match.group(1)
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
                next_elem = header_elem.find_next_sibling()
                if next_elem:
                    if next_elem.name == "ul":
                        items = next_elem.find_all("li")
                        for item in items:
                            pkg = self.parse_version_text(item.get_text(strip=True))
                            if pkg:
                                affected_packages.append(pkg)
                    else:
                        lines = next_elem.get_text("\n").split("\n")
                        for line in lines:
                            pkg = self.parse_version_text(line.strip())
                            if pkg:
                                affected_packages.append(pkg)

        # Clean URL
        # Example: https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/cve-2025-1234?_com_liferay_asset_publisher_web_portlet_AssetPublisherPortlet_INSTANCE_jekt_redirect=...
        if "?" in vuln_url:
            vuln_url = vuln_url.split("?")[0]

        yield AdvisoryData(
            advisory_id=cve_id,
            aliases=[],
            summary=description,
            affected_packages=affected_packages,
            references_v2=[ReferenceV2(url=vuln_url)],
            url=vuln_url,
            severities=severities
        )

    def parse_version_text(self, text):
        if not text:
            return None
            
        if "DXP" in text:
            name = "liferay-dxp"
        elif "Portal" in text:
            name = "liferay-portal"
        else:
            name = "liferay-portal"
            
        purl = PackageURL(type="generic", name=name)
        
        version_match = re.search(r"(\d+\.\d+(\.\d+)?)", text)
        if version_match:
            version = version_match.group(1)
            try:
                affected_range = MavenVersionRange.from_versions([version])
                return AffectedPackageV2(
                    package=purl,
                    affected_version_range=affected_range
                )
            except Exception as e:
                logger.error(f"Failed to parse version {version}: {e}")
                return None
            
        return None
