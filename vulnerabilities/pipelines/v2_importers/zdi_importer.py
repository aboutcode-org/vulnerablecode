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
from datetime import datetime
from datetime import timezone
from typing import Iterable
from xml.etree import ElementTree

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import fetch_response

logger = logging.getLogger(__name__)

ZDI_RSS_YEAR_URL = "https://www.zerodayinitiative.com/rss/published/{year}/"
ZDI_START_YEAR = 2007
ZDI_ID_RE = re.compile(r"ZDI-\d+-\d+")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
PUBDATE_FORMAT = "%a, %d %b %Y %H:%M:%S %z"


class ZDIImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect ZDI security advisories from the Zero Day Initiative RSS feeds."""

    pipeline_id = "zdi_importer"
    spdx_license_expression = "LicenseRef-scancode-proprietary-license"
    license_url = "https://www.zerodayinitiative.com"
    repo_url = "https://www.zerodayinitiative.com"
    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        return 0

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        current_year = datetime.now(tz=timezone.utc).year
        urls = [
            ZDI_RSS_YEAR_URL.format(year=year) for year in range(ZDI_START_YEAR, current_year + 1)
        ]

        seen_ids = set()
        for url in urls:
            self.log(f"Fetching ZDI RSS feed: {url}")
            try:
                response = fetch_response(url)
                items = parse_rss_feed(response.text)
            except Exception as e:
                logger.error("Failed to fetch %s: %s", url, e)
                continue

            for item in items:
                advisory = parse_advisory_data(item)
                if advisory and advisory.advisory_id not in seen_ids:
                    seen_ids.add(advisory.advisory_id)
                    yield advisory


def parse_rss_feed(xml_text: str) -> list:
    """
    Parse ZDI RSS feed XML text and return a list of raw item dicts.
    Each dict has keys: ``title``, ``link``, ``description``, ``pub_date``.
    Returns an empty list if the XML is malformed or has no ``<channel>`` element.
    """
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as e:
        logger.error("Failed to parse RSS XML: %s", e)
        return []

    channel = root.find("channel")
    if channel is None:
        logger.error("RSS feed has no <channel> element")
        return []

    items = []
    for item_el in channel.findall("item"):
        items.append(
            {
                "title": (item_el.findtext("title") or "").strip(),
                "link": (item_el.findtext("link") or "").strip(),
                "description": (item_el.findtext("description") or "").strip(),
                "pub_date": (item_el.findtext("pubDate") or "").strip(),
            }
        )
    return items


def parse_advisory_data(item: dict):
    """
    Parse a single ZDI RSS item dict into an AdvisoryDataV2 object.
    Returns ``None`` if a ZDI advisory ID cannot be extracted from the link URL.
    The RSS feed does not carry structured package data, so ``affected_packages``
    is always empty.
    """
    link = item.get("link") or ""
    title = item.get("title") or ""
    description = item.get("description") or ""
    pub_date_str = item.get("pub_date") or ""

    match = ZDI_ID_RE.search(link)
    if not match:
        logger.error("Could not extract ZDI advisory ID from link: %r", link)
        return None

    advisory_id = match.group(0)
    aliases = list(dict.fromkeys(CVE_RE.findall(description)))

    date_published = None
    if pub_date_str:
        try:
            date_published = datetime.strptime(pub_date_str, PUBDATE_FORMAT)
        except ValueError:
            logger.warning("Could not parse date %r for advisory %s", pub_date_str, advisory_id)

    references = []
    if link:
        references.append(ReferenceV2(url=link))

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=title,
        affected_packages=[],
        references=references,
        date_published=date_published,
        url=link,
    )
