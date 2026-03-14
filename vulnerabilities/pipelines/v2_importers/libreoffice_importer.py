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

import dateparser
import requests
from bs4 import BeautifulSoup

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2

logger = logging.getLogger(__name__)

ADVISORIES_URL = "https://www.libreoffice.org/about-us/security/advisories/"


class LibreOfficeImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect LibreOffice security advisories from libreoffice.org."""

    pipeline_id = "libreoffice_importer"
    spdx_license_expression = "LicenseRef-scancode-proprietary-license"
    license_url = "https://www.libreoffice.org/about-us/security/"
    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self):
        self.log(f"Fetch `{ADVISORIES_URL}`")
        resp = requests.get(ADVISORIES_URL, timeout=30)
        resp.raise_for_status()
        self.advisory_urls = parse_advisory_urls(resp.text)

    def advisories_count(self):
        return len(self.advisory_urls)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for url in self.advisory_urls:
            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
            except Exception as e:
                logger.error("Failed to fetch %s: %s", url, e)
                continue
            advisory = parse_advisory(resp.text, url)
            if advisory:
                yield advisory


def parse_advisory_urls(html: str) -> list:
    """Return deduplicated advisory page URLs from the listing page."""
    slugs = re.findall(r"/about-us/security/advisories/(cve-[\d-]+)/", html)
    seen = dict.fromkeys(slugs)
    return [f"https://www.libreoffice.org/about-us/security/advisories/{slug}/" for slug in seen]


def parse_advisory(html: str, url: str):
    """Parse a LibreOffice individual advisory page; return None if advisory id is missing."""
    soup = BeautifulSoup(html, features="lxml")
    body = soup.find("body")
    body_id = body.get("id", "") if body else ""
    if not body_id.startswith("cve-"):
        return None
    advisory_id = body_id.upper()

    content = soup.select_one("section#content1 div.margin-20")
    if not content:
        return None

    text = content.get_text(separator="\n")

    title = _get_field(text, "Title")
    date_str = _get_field(text, "Announced")

    date_published = None
    if date_str:
        date_published = dateparser.parse(
            date_str,
            settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"},
        )
        if date_published is None:
            logger.warning("Could not parse date %r for %s", date_str, advisory_id)

    desc_m = re.search(
        r"Description\s*\n?\s*:\s*\n+(.*?)(?=\nCredits\b|\nReferences\b|$)",
        text,
        re.DOTALL,
    )
    description = " ".join(desc_m.group(1).split()).strip() if desc_m else ""

    references = []
    in_refs = False
    for tag in content.descendants:
        tag_name = getattr(tag, "name", None)
        if tag_name == "strong" and "References" in tag.get_text():
            in_refs = True
        if in_refs and tag_name == "a":
            href = tag.get("href", "")
            if href.startswith("http"):
                references.append(ReferenceV2(url=href))

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=[],
        summary=description or title,
        affected_packages=[],
        references=references,
        date_published=date_published,
        weaknesses=[],
        severities=[],
        url=url,
        original_advisory_text=str(content),
    )


def _get_field(text: str, label: str) -> str:
    m = re.search(rf"{re.escape(label)}\s*:\s*\n?\s*([^\n]+)", text)
    return m.group(1).strip() if m else ""
