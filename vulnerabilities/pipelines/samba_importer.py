#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import html
import logging
import re
from datetime import datetime
from traceback import format_exc as traceback_format_exc
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional

import pytz
import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_cwe_id


class SambaImporterPipeline(VulnerableCodeBaseImporterPipeline):
    pipeline_id = "samba_importer"
    spdx_license_expression = "GPL-3.0-only"
    license_url = "https://www.samba.org/samba/ms_license.html"
    url = "https://www.samba.org/samba/history/security.html"
    importer_name = "Samba Importer"

    @classmethod
    def steps(cls):
        return (cls.fetch, cls.collect_and_store_advisories, cls.import_new_advisories)

    def fetch(self):
        self.log(f"Fetching `{self.url}`")
        try:
            response = requests.get(self.url)
            response.raise_for_status()
            self.advisory_data = response.text
            self.advisory_details_cache = {}
        except requests.exceptions.HTTPError as http_err:
            self.log(
                f"Failed to fetch Samba security data: {self.url} with error {http_err!r}:\n{traceback_format_exc()}",
                level=logging.ERROR,
            )
            raise

    def advisories_count(self):
        if not hasattr(self, "advisory_data"):
            return 0

        soup = BeautifulSoup(self.advisory_data, "html.parser")
        security_table = soup.find("table", {"class": "security_table"})
        return 0 if not security_table else len(security_table.find_all("tr")) - 1

    def collect_advisories(self):
        soup = BeautifulSoup(self.advisory_data, "html.parser")
        security_table = soup.find("table", {"class": "security_table"})

        if not security_table:
            self.log("Security table not found in HTML content", level=logging.ERROR)
            return

        rows = security_table.find_all("tr")[1:]
        for row in rows:
            try:
                advisory = self.parse_advisory_row(row)
                if advisory:
                    yield advisory
            except Exception as e:
                self.log(
                    f"Error parsing advisory row: {e!r}:\n{traceback_format_exc()}",
                    level=logging.ERROR,
                )

    def get_advisory_details(self, cve_id):
        if cve_id in self.advisory_details_cache:
            return self.advisory_details_cache[cve_id]

        detail_url = f"https://www.samba.org/samba/security/{cve_id}.html"

        try:
            response = requests.get(detail_url)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")
            pre_tag = soup.find("pre")
            if not pre_tag:
                self.log(f"No detailed information found for {cve_id}", level=logging.WARNING)
                return {}

            announcement_text = html.unescape(pre_tag.get_text())
            details = parse_announcement_text(announcement_text)
            details["url"] = detail_url

            self.advisory_details_cache[cve_id] = details
            return details
        except requests.exceptions.RequestException as e:
            self.log(f"Error fetching advisory details for {cve_id}: {e}", level=logging.WARNING)
            return {}
        except Exception as e:
            self.log(f"Error processing advisory details for {cve_id}: {e!r}", level=logging.ERROR)
            return {}

    def parse_advisory_row(self, row):
        cells = row.find_all("td")
        if len(cells) != 6:
            self.log(
                f"Expected 6 cells in security table row, got {len(cells)}", level=logging.WARNING
            )
            return None

        date_issued = cells[0].get_text().strip()
        patch_links = []

        for link in cells[1].find_all("a"):
            href = link.get("href", "")
            if href:
                if not href.startswith(("http://", "https://")):
                    href = f"https://www.samba.org{href}"
                patch_links.append(href)

        issue_desc = cells[2].get_text().strip()
        affected_releases = cells[3].get_text().strip()

        cve_ids = []
        for link in cells[4].find_all("a"):
            cve_id = link.get_text().strip()
            if re.match(r"CVE-\d{4}-\d{4,}", cve_id):
                cve_ids.append(cve_id)

        date_published = None
        try:
            if date_issued:
                date_obj = dateparser.parse(date_issued)
                if date_obj:
                    date_published = date_obj.replace(tzinfo=pytz.UTC)
        except Exception as e:
            self.log(f"Error parsing date {date_issued}: {e!r}", level=logging.WARNING)

        fixed_versions = self.extract_versions_from_patch_links(patch_links)
        affected_packages = []

        if fixed_versions:
            base_purl = PackageURL(type="generic", name="samba")
            for version in fixed_versions:
                affected_packages.append(AffectedPackage(package=base_purl, fixed_version=version))
        elif affected_releases and affected_releases != "Please refer to the advisories.":
            base_purl = PackageURL(type="generic", name="samba")
            version_match = re.search(r"(?:Samba|samba)\s+(\d+\.\d+\.\d+)", affected_releases)

            if version_match:
                affected_packages.append(
                    AffectedPackage(
                        package=base_purl, fixed_version=f"{version_match.group(1)}-fixed"
                    )
                )
            else:
                affected_packages.append(
                    AffectedPackage(package=base_purl, fixed_version="unknown")
                )

        if not cve_ids and issue_desc:
            synthetic_id = (
                f"SAMBA-VULN-{date_issued.replace(' ', '-') if date_issued else 'UNKNOWN'}"
            )
            cve_ids.append(synthetic_id)

        detailed_summary = issue_desc

        for cve_id in cve_ids:
            details = self.get_advisory_details(cve_id)
            if not details:
                continue

            if details.get("summary"):
                detailed_summary = details["summary"]

            if details.get("description"):
                detailed_summary = f"{detailed_summary}\n\n{details['description']}"

            if details.get("affected_versions"):
                versions_details = details.get("affected_versions")
                fixed_vers = details.get("fixed_versions", [])

                for pkg in self.extract_affected_packages_from_detail(versions_details, fixed_vers):
                    affected_packages.append(pkg)

            if details.get("mitigation"):
                detailed_summary = f"{detailed_summary}\n\nMitigation: {details['mitigation']}"

        references = []
        for link in cells[5].find_all("a"):
            announcement_text = link.get_text().strip()
            announcement_url = link.get("href")
            if announcement_url:
                if not announcement_url.startswith(("http://", "https://")):
                    announcement_url = f"https://www.samba.org{announcement_url}"

                reference_id = None
                for cve_id in cve_ids:
                    if cve_id in announcement_url:
                        reference_id = cve_id
                        break

                if not reference_id:
                    reference_id = announcement_text

                references.append(Reference(url=announcement_url, reference_id=reference_id))

        for patch_url in patch_links:
            patch_filename = patch_url.split("/")[-1]
            references.append(Reference(url=patch_url, reference_id=f"Patch: {patch_filename}"))

        return AdvisoryData(
            aliases=cve_ids,
            summary=build_description(
                summary=detailed_summary, description=f"Affected versions: {affected_releases}"
            ),
            references=references,
            affected_packages=affected_packages,
            date_published=date_published,
            url="https://www.samba.org/samba/history/security.html",
        )

    def extract_affected_packages_from_detail(self, affected_versions, fixed_versions=None):
        affected_packages = []
        fixed_versions = fixed_versions or []
        base_purl = PackageURL(type="generic", name="samba")

        if fixed_versions:
            for version in fixed_versions:
                affected_packages.append(AffectedPackage(package=base_purl, fixed_version=version))
        elif affected_versions:
            version_match = re.search(r"(?:Samba|samba)\s+(\d+\.\d+\.\d+)", affected_versions)
            if version_match:
                affected_packages.append(
                    AffectedPackage(
                        package=base_purl, fixed_version=f"{version_match.group(1)}-fixed"
                    )
                )
            else:
                affected_packages.append(
                    AffectedPackage(package=base_purl, fixed_version="unknown")
                )

        return affected_packages

    def extract_versions_from_patch_links(self, patch_links):
        versions = []
        for link in patch_links:
            match = re.search(r"samba-(\d+\.\d+\.\d+(?:\.\d+)?)", link)
            if match:
                version = match.group(1)
                if version not in versions:
                    versions.append(version)
        return versions


def extract_cwe_ids(issue_desc):
    cwe_ids = []
    for cwe_match in re.findall(r"CWE-(\d+)", issue_desc):
        try:
            cwe_ids.append(int(cwe_match))
        except ValueError:
            pass
    return cwe_ids


def parse_announcement_text(text):
    result = {
        "subject": None,
        "cve_id": None,
        "affected_versions": None,
        "summary": None,
        "description": None,
        "patches": None,
        "mitigation": None,
        "credits": None,
        "fixed_versions": [],
    }

    cve_match = re.search(r"CVE ID#:\s*(CVE-\d+-\d+)", text, re.IGNORECASE)
    if cve_match:
        result["cve_id"] = cve_match.group(1)

    subject_match = re.search(r"== Subject:\s*(.*?)(?=\n==\nCVE|\n==\n==)", text, re.DOTALL)
    if subject_match:
        subject = subject_match.group(1).strip()
        subject = re.sub(r"\n==\s*", " ", subject)
        subject = re.sub(r"\s+", " ", subject)
        result["subject"] = subject

    versions_match = re.search(r"Versions:\s*(.*?)(?=\n\n|\n==|\n[A-Za-z]+:)", text, re.DOTALL)
    if versions_match:
        result["affected_versions"] = versions_match.group(1).strip()

    summary_match = re.search(r"Summary:\s*(.*?)(?=\n\n|\n==|\n[A-Za-z]+:)", text, re.DOTALL)
    if summary_match:
        summary = summary_match.group(1).strip()
        summary = re.sub(r"\n==\s*", " ", summary)
        summary = re.sub(r"\s*==\s*", " ", summary)
        result["summary"] = summary

    sections = re.split(r"={2,}\n([A-Za-z ]+)\n={2,}", text)[1:]

    for i in range(0, len(sections), 2):
        if i + 1 < len(sections):
            section_name = sections[i].strip().lower()
            section_content = sections[i + 1].strip()

            if section_name == "description":
                result["description"] = section_content
            elif section_name == "patch availability":
                result["patches"] = section_content
                fixed_versions = re.findall(r"Samba\s+(\d+\.\d+\.\d+(?:\.\d+)?)", section_content)
                if fixed_versions:
                    result["fixed_versions"] = fixed_versions
            elif section_name == "workaround and mitigating factors":
                result["mitigation"] = section_content
            elif section_name == "credits":
                result["credits"] = section_content

    return result
