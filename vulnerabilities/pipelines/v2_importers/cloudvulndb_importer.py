#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import json
import logging
from typing import Iterable
from urllib.parse import urlparse
from xml.etree import ElementTree

from dateutil import parser as dateutil_parser

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import find_all_cve

logger = logging.getLogger(__name__)

CLOUDVULNDB_RSS_URL = "https://www.cloudvulndb.org/rss/feed.xml"


class CloudVulnDBImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect cloud vulnerabilities from the public CloudVulnDB RSS feed."""

    pipeline_id = "cloudvulndb_importer_v2"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/wiz-sec/open-cvdb/blob/main/LICENSE.md"
    repo_url = "https://github.com/wiz-sec/open-cvdb"
    precedence = 200

    _cached_items = None

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def get_feed_items(self):
        if self._cached_items is None:
            response = fetch_response(CLOUDVULNDB_RSS_URL)
            self._cached_items = parse_rss_feed(response.text)
        return self._cached_items

    def advisories_count(self) -> int:
        return len(self.get_feed_items())

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for item in self.get_feed_items():
            advisory = parse_advisory_data(item)
            if advisory:
                yield advisory


def parse_rss_feed(xml_text: str) -> list:
    """
    Parse CloudVulnDB RSS XML and return a list of item dictionaries.
    Each dictionary has ``title``, ``link``, ``description``, ``pub_date`` and ``guid`` keys.
    """
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as e:
        logger.error("Failed to parse CloudVulnDB RSS XML: %s", e)
        return []

    channel = root.find("channel")
    if channel is None:
        logger.error("CloudVulnDB RSS feed has no <channel> element")
        return []

    items = []
    for item_el in channel.findall("item"):
        items.append(
            {
                "title": (item_el.findtext("title") or "").strip(),
                "link": (item_el.findtext("link") or "").strip(),
                "description": (item_el.findtext("description") or "").strip(),
                "pub_date": (item_el.findtext("pubDate") or "").strip(),
                "guid": (item_el.findtext("guid") or "").strip(),
            }
        )

    return items


def parse_advisory_data(item: dict):
    """
    Parse one CloudVulnDB item and return an AdvisoryDataV2 object.
    Since the RSS feed does not provide package/version coordinates, ``affected_packages`` is empty.
    """
    title = item.get("title") or ""
    link = item.get("link") or ""
    description = item.get("description") or ""
    pub_date = item.get("pub_date") or ""
    guid = item.get("guid") or ""

    advisory_id = get_advisory_id(guid=guid, link=link, title=title, pub_date=pub_date)
    if not advisory_id:
        logger.error("Skipping advisory with no usable identifier: %r", item)
        return None

    aliases = list(dict.fromkeys(find_all_cve(f"{title}\n{description}")))
    aliases = [alias for alias in aliases if alias != advisory_id]

    date_published = None
    if pub_date:
        try:
            date_published = dateutil_parser.parse(pub_date)
        except Exception as e:
            logger.warning("Could not parse date %r for advisory %s: %s", pub_date, advisory_id, e)

    references = []
    if link:
        references.append(ReferenceV2(url=link))

    summary = title or description

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=summary,
        affected_packages=[],
        references=references,
        date_published=date_published,
        url=link or CLOUDVULNDB_RSS_URL,
        original_advisory_text=json.dumps(item, indent=2, ensure_ascii=False),
    )


def get_advisory_id(guid: str, link: str, title: str, pub_date: str) -> str:
    """
    Return a stable advisory identifier using the best available source.
    Preference order is GUID, link slug, then deterministic content hash fallback.
    """
    guid = (guid or "").strip()
    if guid:
        return guid

    slug = advisory_slug_from_link(link)
    if slug:
        return slug

    fingerprint_source = "|".join([title.strip(), pub_date.strip()])
    if not fingerprint_source.strip("|"):
        return ""

    digest = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()[:16]
    return f"cloudvulndb-{digest}"


def advisory_slug_from_link(link: str) -> str:
    """Extract an advisory slug from a CloudVulnDB URL path."""
    if not link:
        return ""

    try:
        parsed = urlparse(link)
    except Exception:
        return ""

    parts = [part for part in parsed.path.split("/") if part]
    if not parts:
        return ""

    return parts[-1].strip()
