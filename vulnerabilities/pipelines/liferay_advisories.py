import requests
from bs4 import BeautifulSoup
from django.db import transaction
from fake_useragent import UserAgent
from packageurl import PackageURL
from requests.exceptions import HTTPError
from requests.exceptions import RequestException
from requests.exceptions import Timeout

from vulnerabilities.models import Advisory
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.pipelines import VulnerableCodePipeline


class LiferayAdvisoryPipeline(VulnerableCodePipeline):
    pipeline_id = "liferay_advisories"
    description = "Import Liferay security advisories"
    license_url = "https://liferay.dev/portal/security/known-vulnerabilities"
    spdx_license_expression = "CC-BY-4.0"

    @classmethod
    def steps(cls):
        return (
            cls.fetch_advisories,
            cls.parse_advisories,
            cls.import_to_db,
        )

    def fetch_advisories(self):
        try:
            ua = UserAgent()
            response = requests.get(
                "https://liferay.dev/portal/security/known-vulnerabilities",
                headers={"User-Agent": ua.chrome},
                timeout=30,
            )
            response.raise_for_status()

            if not response.text.strip():
                raise ValueError("Empty response from server")

            self.html_content = response.text

        except Timeout as te:
            self.log(f"Timeout occurred: {te}")
            raise
        except HTTPError as he:
            self.log(f"HTTP Error {he.response.status_code}: {he}")
            if he.response.status_code == 403:
                self.log("Consider rotating User-Agent headers")
            raise
        except RequestException as re:
            self.log(f"Request failed: {re}")
            raise
        except Exception as e:
            self.log(f"Unexpected error: {e}")
            raise RuntimeError(f"Fatal pipeline error: {e}") from e

    def parse_advisories(self):
        self.parsed_advisories = []
        soup = BeautifulSoup(self.html_content, "html.parser")

        portlet_section = soup.select_one("section.portlet")
        if not portlet_section:
            self.log("No portlet section found")
            return

        # Loop over advisories
        for asset_entry in portlet_section.select(".asset-entry, .entry, .asset-publisher"):
            try:
                cve_id = asset_entry.select_one("h1, h2, h3, .entry-title").get_text(strip=True)
            except AttributeError:
                self.log("No title found; skipping entry.")
                continue

            if not cve_id.startswith("CVE-"):
                self.log(f"Skipping non-CVE entry: {cve_id}")
                continue

            try:
                description = asset_entry.select_one(".entry-content, .asset-content").get_text(
                    " ", strip=True
                )

                metadata = asset_entry.select_one(".metadata, .entry-metadata")
                if not metadata:
                    self.log(f"No metadata found for {cve_id}; skipping.")
                    continue

                # Attempt to parse severity and versions
                severity_tag = metadata.select_one(".severity:contains('Severity') + dd")
                severity = severity_tag.get_text(strip=True) if severity_tag else "Unknown"

                affected_versions = [
                    li.get_text(strip=True)
                    for li in metadata.select(".affected-versions li, .versions li")
                ]

                # Extract references
                references = [
                    a["href"]
                    for a in asset_entry.select(".references a, .external-links a")
                    if a.has_attr("href")
                ]

                self.parsed_advisories.append(
                    {
                        "cve_id": cve_id,
                        "summary": description,
                        "severity": severity,
                        "affected_versions": affected_versions,
                        "references": references,
                    }
                )
            except Exception as e:
                self.log(f"Skipping invalid advisory block for {cve_id}: {str(e)}")
                continue

    @transaction.atomic
    def import_to_db(self):
        if not hasattr(self, "parsed_advisories"):
            self.log("No advisories to import.")
            return

        for data in self.parsed_advisories:
            vuln, _ = Vulnerability.objects.get_or_create(
                vulnerability_id=data["cve_id"],
                defaults={
                    "summary": data["summary"],
                    "severity": data["severity"],
                },
            )

            # If references exist, create first reference
            if data["references"]:
                VulnerabilityReference.objects.get_or_create(
                    vulnerability=vuln, url=data["references"][0]
                )

            # Create AffectedPackage records
            for version in data["affected_versions"]:
                parsed_version = self.parse_versions(version)
                purl_str = PackageURL(
                    type="liferay",
                    name="dxp" if "dxp" in parsed_version.lower() else "portal",
                    version=parsed_version,
                ).to_string()
                # Do something with purl_str, e.g., store in your DB or logs
                self.log(f"Affected version PURL: {purl_str}")

        self.log(f"Imported {len(self.parsed_advisories)} Liferay advisories")

    def parse_versions(self, text):
        if "DXP" in text:
            return f"liferay-dxp-{text.split()[-1].lower()}"
        return f"liferay-portal-{text.split()[0]}"
