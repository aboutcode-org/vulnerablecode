#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import json
import logging
from typing import Iterable

import dateparser
import requests
from bs4 import BeautifulSoup

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC

logger = logging.getLogger(__name__)

ADVISORY_BASE_URL = "https://advisories.checkpoint.com"
ADVISORY_LIST_URL = "https://advisories.checkpoint.com/advisories/"


class CheckPointImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect Check Point security advisories."""

    pipeline_id = "checkpoint_importer"
    spdx_license_expression = "LicenseRef-scancode-proprietary-license"
    license_url = "https://advisories.checkpoint.com/"
    url = ADVISORY_LIST_URL
    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self):
        self.log(f"Fetch `{self.url}`")
        self.advisories_data = list(fetch_all_advisory_rows(self.log))

    def advisories_count(self):
        return len(self.advisories_data)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for row_data in self.advisories_data:
            advisory = parse_advisory(row_data)
            if advisory:
                yield advisory


def get_available_years(soup: BeautifulSoup) -> list:
    """Return sorted list of years from year-navigation links, including current year."""
    years = set()
    for link in soup.find_all("a", href=True):
        href = link["href"]
        if "/defense/advisories/public/" in href:
            part = href.rstrip("/").split("/")[-1]
            if part.isdigit() and len(part) == 4:
                years.add(int(part))
    years.add(datetime.date.today().year)
    return sorted(years)


def get_total_pages(soup: BeautifulSoup) -> int:
    """Return total page count from pagination links."""
    page_nums = []
    for link in soup.find_all("a", href=True):
        href = link["href"]
        if "/advisories/page/" in href:
            part = href.split("/page/")[-1].split("?")[0].strip("/")
            if part.isdigit():
                page_nums.append(int(part))
    return max(page_nums) if page_nums else 1


def fetch_all_advisory_rows(log_fn) -> Iterable[dict]:
    """Yield row dicts for all advisories across all years and pages."""
    try:
        resp = requests.get(ADVISORY_LIST_URL, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        log_fn(f"Failed to fetch {ADVISORY_LIST_URL}: {e}")
        return

    soup = BeautifulSoup(resp.text, features="lxml")
    years = get_available_years(soup)
    if not years:
        log_fn("No years found on advisories page")
        return

    for year in years:
        url = f"{ADVISORY_LIST_URL}?year={year}"
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            log_fn(f"Failed to fetch {url}: {e}")
            continue

        year_soup = BeautifulSoup(resp.text, features="lxml")
        total_pages = get_total_pages(year_soup)
        yield from parse_table_rows(resp.text)

        for page in range(2, total_pages + 1):
            page_url = f"{ADVISORY_LIST_URL}page/{page}/?year={year}"
            try:
                resp = requests.get(page_url, timeout=30)
                resp.raise_for_status()
            except requests.exceptions.RequestException as e:
                log_fn(f"Failed to fetch {page_url}: {e}")
                break
            yield from parse_table_rows(resp.text)


def parse_table_rows(html: str) -> list:
    """Return list of row dicts from the advisories table HTML."""
    soup = BeautifulSoup(html, features="lxml")
    table = soup.find("table", {"id": "cp_advisory_table_sorter"})
    if not table:
        return []

    rows = []
    for tr in table.find_all("tr")[1:]:
        cells = tr.find_all("td")
        # 7 cols: Severity, Date Published, Date Updated, CPAI Ref, Source, Industry Ref, Description
        if len(cells) < 7:
            continue

        cpai_link = cells[3].find("a")
        if not cpai_link:
            continue

        advisory_id = cpai_link.get_text(strip=True)
        href = cpai_link.get("href", "")
        advisory_url = f"{ADVISORY_BASE_URL}{href}" if href.startswith("/") else href

        cve_link = cells[5].find("a")
        cve_text = cve_link.get_text(strip=True) if cve_link else cells[5].get_text(strip=True)
        # strip " (and N others)" if present
        cve_id = cve_text.split(" (")[0].strip()

        summary_link = cells[6].find("a")
        summary = (
            summary_link.get_text(strip=True) if summary_link else cells[6].get_text(strip=True)
        )

        rows.append(
            {
                "advisory_id": advisory_id,
                "advisory_url": advisory_url,
                "cve_id": cve_id,
                "severity": cells[0].get_text(strip=True),
                "date_published": cells[1].get_text(strip=True),
                "summary": summary,
            }
        )

    return rows


def parse_advisory(row_data: dict):
    """Return AdvisoryDataV2 from a row data dict, or None if advisory_id is missing."""
    advisory_id = row_data.get("advisory_id") or ""
    if not advisory_id or not advisory_id.startswith("CPAI-"):
        return None

    date_published = None
    raw_date = row_data.get("date_published") or ""
    if raw_date:
        date_published = dateparser.parse(
            raw_date,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"},
        )
        if date_published is None:
            logger.warning("Could not parse date %r for %s", raw_date, advisory_id)

    cve_id = row_data.get("cve_id") or ""
    aliases = [cve_id] if cve_id.startswith("CVE-") else []

    advisory_url = row_data.get("advisory_url") or ""
    references = []
    if advisory_url:
        references.append(ReferenceV2(url=advisory_url, reference_id=advisory_id))
    if cve_id.startswith("CVE-"):
        references.append(
            ReferenceV2(
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                reference_id=cve_id,
            )
        )

    severities = []
    severity = row_data.get("severity") or ""
    if severity:
        severities.append(VulnerabilitySeverity(system=GENERIC, value=severity))

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=row_data.get("summary") or "",
        affected_packages=[],
        references=references,
        date_published=date_published,
        weaknesses=[],
        severities=severities,
        url=advisory_url,
        original_advisory_text=json.dumps(row_data, indent=2, ensure_ascii=False),
    )
