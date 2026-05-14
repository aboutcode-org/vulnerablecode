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
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
from xml.etree import ElementTree

from dateutil import parser as dateutil_parser
from fetchcode.vcs import fetch_via_vcs
import saneyaml

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import find_all_cve

logger = logging.getLogger(__name__)

CLOUDVULNDB_RSS_URL = "https://www.cloudvulndb.org/rss/feed.xml"


class CloudVulnDBImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect cloud vulnerabilities from CloudVulnDB structured data files."""

    pipeline_id = "cloudvulndb_importer_v2"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/wiz-sec/open-cvdb/blob/main/LICENSE.md"
    repo_url = "https://github.com/wiz-sec/open-cvdb"
    precedence = 200

    _cached_items = None

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()

    def _iter_structured_files(self):
        base_directory = Path(self.vcs_response.dest_dir)

        for file_path in base_directory.rglob("*"):
            if not file_path.is_file():
                continue

            suffix = file_path.suffix.lower()
            if suffix not in (".json", ".yaml", ".yml"):
                continue

            yield file_path

    def _load_file_items(self, file_path: Path):
        text = file_path.read_text(encoding="utf-8", errors="replace")
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            data = json.loads(text)
        else:
            data = saneyaml.load(text)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            for key in ("vulnerabilities", "advisories", "items", "data"):
                nested = data.get(key)
                if isinstance(nested, list):
                    return nested
            return [data]

        return []

    def get_feed_items(self):
        if self._cached_items is None:
            response = fetch_response(CLOUDVULNDB_RSS_URL)
            self._cached_items = parse_rss_feed(response.text)
        return self._cached_items

    def advisories_count(self) -> int:
        count = 0
        for file_path in self._iter_structured_files():
            try:
                count += len(self._load_file_items(file_path))
            except Exception:
                continue

        if count:
            return count

        return len(self.get_feed_items())

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        base_directory = Path(self.vcs_response.dest_dir)
        structured_count = 0

        for file_path in self._iter_structured_files():
            try:
                items = self._load_file_items(file_path)
            except Exception as e:
                self.log(
                    f"Failed to parse structured file {file_path}: {e}",
                    level=logging.WARNING,
                )
                continue

            if not items:
                continue

            advisory_url = get_advisory_url(
                file=file_path,
                base_path=base_directory,
                url="https://github.com/wiz-sec/open-cvdb/blob/main/",
            )

            for item in items:
                advisory = parse_structured_advisory_data(item=item, advisory_url=advisory_url)
                if advisory:
                    structured_count += 1
                    yield advisory

        if structured_count:
            return

        self.log("No structured YAML/JSON advisories found, falling back to RSS feed")
        for item in self.get_feed_items():
            advisory = parse_rss_advisory_data(item)
            if advisory:
                yield advisory


def parse_structured_advisory_data(item: dict, advisory_url: str):
    """
    Parse one structured advisory object from YAML/JSON.

    This parser is intentionally tolerant and can emit advisories without packages,
    which is required for SaaS advisories where a PURL may not exist yet.
    """
    if not isinstance(item, dict):
        return None

    advisory_id = (
        item.get("id")
        or item.get("advisory_id")
        or item.get("uid")
        or item.get("slug")
        or item.get("name")
        or ""
    )
    advisory_id = str(advisory_id).strip()

    title = str(item.get("title") or item.get("summary") or "").strip()
    description = str(item.get("description") or item.get("details") or "").strip()

    date_value = item.get("published") or item.get("published_at") or item.get("date")
    date_published = None
    if date_value:
        try:
            date_published = dateutil_parser.parse(str(date_value))
        except Exception:
            date_published = None

    aliases = []
    alias_candidates = item.get("aliases")
    if isinstance(alias_candidates, list):
        for alias in alias_candidates:
            alias_text = str(alias).strip()
            if alias_text:
                aliases.extend(find_all_cve(alias_text) or [alias_text])

    for key in ("cve", "cve_id", "cve_ids"):
        value = item.get(key)
        if isinstance(value, str):
            aliases.extend(find_all_cve(value))
        elif isinstance(value, list):
            for entry in value:
                aliases.extend(find_all_cve(str(entry)))

    # Structured records often only mentio CVEs in free text fields.
    aliases.extend(find_all_cve(description))
    aliases.extend(find_all_cve(title))

    aliases = list(dict.fromkeys([a for a in aliases if a]))

    if not advisory_id:
        advisory_id = get_advisory_id(
            guid="",
            link=advisory_url,
            title=title,
            pub_date=str(date_value or ""),
        )

    if not advisory_id:
        return None

    references = []
    reference_urls = []
    refs = item.get("references")
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, str):
                reference_urls.append(ref)
                continue

            if isinstance(ref, dict):
                for key in ("url", "href", "link"):
                    if ref.get(key):
                        reference_urls.append(str(ref.get(key)))
                        break

    source_url = item.get("url") or item.get("source") or advisory_url
    if source_url:
        reference_urls.append(str(source_url))

    for url in list(dict.fromkeys([u.strip() for u in reference_urls if str(u).strip()])):
        references.append(ReferenceV2(url=url))

    summary = title or description or advisory_id

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=[alias for alias in aliases if alias != advisory_id],
        summary=summary,
        affected_packages=[],
        references=references,
        date_published=date_published,
        url=advisory_url,
        original_advisory_text=json.dumps(item, indent=2, ensure_ascii=False),
    )


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


def parse_rss_advisory_data(item: dict):
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


# Backward-compatible alias used by existing tests/imports.
parse_advisory_data = parse_rss_advisory_data


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
